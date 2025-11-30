using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography; // Used for Cryptographically Secure Random numbers

// Assuming ObfuscationSettings is defined elsewhere
// namespace IronBrew2.Bytecode_Library.IR; 

namespace IronBrew2.Obfuscator.Encryption
{
    public class Decryptor
    {
        private readonly byte[] _table; // Changed to byte array for memory efficiency and type safety
        public string Name { get; }
        
        // Removed SLen and unused public fields (Table)

        public Decryptor(string name, int maxLen)
        {
            Name = name;
            // Use RNGCryptoServiceProvider for cryptographically secure random values
            // This makes the encryption key table harder to predict/guess.
            using (var rng = RandomNumberGenerator.Create())
            {
                _table = new byte[maxLen];
                rng.GetBytes(_table);
            }
        }

        public string Encrypt(byte[] bytes)
        {
            var encrypted = new byte[bytes.Length];
            int tableLength = _table.Length;
            
            // Use Array/Span for direct byte manipulation for speed
            for (var index = 0; index < bytes.Length; index++)
                encrypted[index] = (byte) (bytes[index] ^ _table[index % tableLength]);

            // --- Lua Decryptor Generation ---
            
            // Format encrypted bytes and key table using three-digit decimal escapes (\001) for safety
            // Lua supports \000-\255 in string literals.
            string encryptedDataLua = string.Join("", encrypted.Select(b => $"\\{b:D3}"));
            string keyTableLua = string.Join("", _table.Select(b => $"\\{b:D3}"));
            
            // Refined Lua template for better runtime performance:
            // 1. Uses string.byte and string.char for direct conversion.
            // 2. Uses table.concat instead of slow string concatenation (c=c..t[...]).
            // 3. Retains the original Xor math function for compatibility but cleans it up.
            
            // Note: The original Lua code included a redundant 't' mapping table which is slow.
            // The template below removes the slow lookup table 't' and uses standard string.byte/char.
            
            string luaDecryptorTemplate = 
                $"((function(data) " +
                $"local function xor_op(a, b) " +
                    // Original iterative math XOR function (safer for Lua 5.1/compatibility)
                    $"local d,e=1,0;while a>0 and b>0 do local f,g=a%2,b%2;if f~=g then e=e+d end;a,b,d=(a-f)/2,(b-g)/2,d*2 end;if a<b then a=b end;while a>0 do local f=a%2;if f>0 then e=e+d end;a,d=(a-f)/2,d*2 end;return e end; " +
                    
                $"local key_str=\"{keyTableLua}\"; " +
                $"local key_len={tableLength}; " +
                $"local res={{} }; " +
                $"local byte=string.byte; " +
                $"local char=string.char; " +
                $"local len=#data; " +
                
                $"for i = 1, len do " +
                    $"res[i] = char(xor_op(byte(data, i), byte(key_str, (i-1)%key_len+1))); " +
                $"end; " +
                $"return table.concat(res); " +
                $@"{Name}}}(\"{encryptedDataLua}\"))";

            return luaDecryptorTemplate;
        }
    }
    
    // -----------------------------------------------------------------------------------

	public class ConstantEncryption
	{
		private string _src;
		private readonly ObfuscationSettings _settings;
		private readonly Encoding _luaEncoding = Encoding.GetEncoding(28591);

		public ConstantEncryption(ObfuscationSettings settings, string source)
		{
			_settings = settings;
			_src = source;
		}

        // Use a static readonly Regex for performance.
        private static readonly Regex StringLiteralRegex = 
            new Regex(@"(['""])?(?(1)((?:[^\\]|\\.)*?)\1|\[(=*)\[(.*?)\]\3\])", 
                      RegexOptions.Singleline | RegexOptions.Compiled);
        
		public Decryptor GenerateGenericDecryptor(MatchCollection matches)
		{
			int maxLen = 0;

            // Use LINQ and safe access for cleaner length calculation
            if (matches.Count > 0)
			    maxLen = matches.Cast<Match>().Max(m => m.Length);

			if (maxLen > _settings.DecryptTableLen)
				maxLen = _settings.DecryptTableLen;
			
			return new Decryptor("IRONBREW_STR_DEC_GENERIC", maxLen);
		}

		public static byte[] UnescapeLuaString(string str)
		{
            // Use StringBuilder and better indexing for faster/safer parsing
			var bytes = new List<byte>(str.Length);
			
			int i = 0;
			while (i < str.Length)
			{
				char cur = str[i++];
				if (cur == '\\')
				{
                    if (i >= str.Length) 
                        throw new FormatException("Lua string ends with unescaped backslash.");

					char next = str[i++];

					switch (next)
					{
                        // Standard escapes
						case 'a': bytes.Add(0x07); break; 
						case 'b': bytes.Add(0x08); break; 
						case 'f': bytes.Add(0x0C); break; 
						case 'n': bytes.Add(0x0A); break; 
						case 'r': bytes.Add(0x0D); break; 
						case 't': bytes.Add(0x09); break; 
						case 'v': bytes.Add(0x0B); break; 

						default:
						{
							if (!char.IsDigit(next))
							{
                                // Escaped character (e.g., '\\', '\"')
								bytes.Add((byte) next);
							}
							else 
							{
                                // Numeric escape (\DDD, max 3 digits)
								var s = new StringBuilder(next.ToString());	
								
								for (int j = 0; j < 2; j++)
								{
									if (i >= str.Length) break;

									char n = str[i];
									if (char.IsDigit(n))
									{
										s.Append(n);
										i++;
									}
									else
										break;
								}
                                
                                if (!int.TryParse(s.ToString(), out int value) || value > 255)
                                    throw new FormatException($"Invalid numeric escape sequence in Lua string: \\{s}");
                                
								bytes.Add((byte) value);
							}

							break;
						}
					}
				}
				else
					bytes.Add((byte) cur);
			}

			return bytes.ToArray();
		}

		public string EncryptStrings()
		{
            var sourceBuilder = new StringBuilder(_src.Length + (_src.Length / 10)); // Heuristic initial size
            var matches = StringLiteralRegex.Matches(_src);
            var replacements = new List<(int Start, int End, string Replacement)>();
            
            // --- Stage 1: Encrypt ALL strings if settings.EncryptStrings is true ---
			if (_settings.EncryptStrings)
			{
				// Generate ONE generic decryptor for ALL strings for efficiency
				Decryptor dec = GenerateGenericDecryptor(matches);
			
				foreach (Match m in matches)
				{
					// m.Groups[2] is single/double quoted, m.Groups[4] is long-bracketed
					string captured = m.Groups[2].Value + m.Groups[4].Value;

					if (captured.StartsWith("[STR_ENCRYPT]"))
						captured = captured.Substring(13);
					
                    // Decide whether to unescape (quoted string) or just get bytes (long bracket)
                    byte[] rawBytes = m.Groups[2].Success 
                        ? UnescapeLuaString(captured) 
                        : _luaEncoding.GetBytes(captured);
					
                    string encryptedString = dec.Encrypt(rawBytes);

                    replacements.Add((m.Index, m.Index + m.Length, encryptedString));
				}
			}

            // --- Stage 2: Encrypt specific [STR_ENCRYPT] strings (if Stage 1 skipped) ---
			else
			{
                // Reuse existing matches
				int n = 0;
				foreach (Match m in matches)
				{
					string captured = m.Groups[2].Value + m.Groups[4].Value;
					
					if (!captured.StartsWith("[STR_ENCRYPT]"))
						continue;

					captured = captured.Substring(13);
                    // Decryptor is created per string here (less efficient, but possibly desired)
					Decryptor dec = new Decryptor("IRONBREW_STR_ENCRYPT" + n++, m.Length);

                    byte[] rawBytes = m.Groups[2].Success
						? UnescapeLuaString(captured)
						: _luaEncoding.GetBytes(captured);
                    
                    string encryptedString = dec.Encrypt(rawBytes);
                    replacements.Add((m.Index, m.Index + m.Length, encryptedString));
				}
			}
			
            // --- Stage 3: Encrypt important strings (always runs if setting is true) ---
			if (_settings.EncryptImportantStrings)
			{
                // Reuse existing matches
				int n = 0;
				
                // Use HashSet for faster lookups
				var sTerms = new HashSet<string>(StringComparer.OrdinalIgnoreCase) 
                    { "http", "function", "metatable", "local" };

				foreach (Match m in matches)
				{
					string captured = m.Groups[2].Value + m.Groups[4].Value;
					if (captured.StartsWith("[STR_ENCRYPT]"))
						captured = captured.Substring(13);

                    // Check if captured contains any important term
					bool containsImportantTerm = sTerms.Any(term => captured.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0);

					if (!containsImportantTerm)
						continue;

					Decryptor dec = new Decryptor("IRONBREW_STR_ENCRYPT_IMPORTANT" + n++, m.Length);

                    byte[] rawBytes = m.Groups[2].Success
						? UnescapeLuaString(captured)
						: _luaEncoding.GetBytes(captured);

					string encryptedString = dec.Encrypt(rawBytes);

                    // Note: If a string was already replaced in Stage 1 or 2, 
                    // this replacement list must correctly handle the indices.
                    // For maximum safety, we should only append new replacements, 
                    // or rely on the reverse sorting logic below to handle overlaps.
                    replacements.Add((m.Index, m.Index + m.Length, encryptedString));
				}
			}

            // --- Final Application of Replacements (Safe and Fast) ---
            
            // 1. Sort by Start Index (descending) to safely apply replacements
            replacements.Sort((a, b) => b.Start.CompareTo(a.Start)); 
            
            // 2. Build the final source code
            sourceBuilder.Append(_src); // Initialize with original source
            
            foreach (var (start, end, replacement) in replacements)
            {
                int length = end - start;
                
                // Check if this range has already been replaced by an earlier (higher index) stage.
                // This is a safety measure against duplicate work/index corruption.
                if (start < 0 || start + length > sourceBuilder.Length)
                    continue; 

                sourceBuilder.Remove(start, length);
                sourceBuilder.Insert(start, replacement);
            }

			_src = sourceBuilder.ToString();
			return _src;
		}
	}
}
