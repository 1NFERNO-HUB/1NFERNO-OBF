using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using IronBrew2.Bytecode_Library.IR;

namespace IronBrew2.Bytecode_Library.Bytecode
{
	public class ObfuscatedSerializer
	{
		private readonly Chunk _chunk;
		// Use a standard encoding or a custom one for the obfuscator
		private readonly Encoding _luaEncoding = Encoding.GetEncoding(28591); 
        
        // --- Obfuscation Configuration ---
        private readonly byte[] _magicBytes = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }; // New, custom magic number
        private readonly byte _customVersion = 0x80;                                   // Custom version byte
        private readonly byte _customEndianness = 0xAA;                                // Custom endianness marker

        // Dynamically shuffled mapping of OpCodes to obfuscated indices
        private readonly Dictionary<Opcode, uint> _shuffledOpcodeMap;

		public ObfuscatedSerializer(Chunk chunk)
		{
			_chunk = chunk;
            _shuffledOpcodeMap = GenerateShuffledOpcodeMap();
		}
        
        // --- Obfuscation Logic ---

        // Step 1: Create a random mapping from standard OpCodes to new indices (0-39)
        private Dictionary<Opcode, uint> GenerateShuffledOpcodeMap()
        {
            var opcodes = Enum.GetValues(typeof(Opcode)).Cast<Opcode>().Where(op => (int)op >= 0 && (int)op <= 39).ToList();
            var shuffledIndices = Enumerable.Range(0, opcodes.Count).OrderBy(x => Guid.NewGuid()).ToList();
            
            var map = new Dictionary<Opcode, uint>();
            for (int i = 0; i < opcodes.Count; i++)
            {
                map[opcodes[i]] = (uint)shuffledIndices[i];
            }
            return map;
        }
        
        // Simple XOR encryption for constants/strings
        private byte[] SimpleXOREncrypt(byte[] data, byte key)
        {
            var encrypted = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                encrypted[i] = (byte)(data[i] ^ key);
            }
            return encrypted;
        }

        // --- Serialization Helpers (Modified for obfuscation) ---

		public byte[] Serialize()
		{
			var res = new List<byte>();

			void WriteByte(byte b) => res.Add(b);
			void WriteBytes(byte[] bs) => res.AddRange(bs);
			void WriteInt(int i) => WriteBytes(BitConverter.GetBytes(i));
			void WriteUInt(uint i) => WriteBytes(BitConverter.GetBytes(i));
			void WriteDouble(double d) => WriteBytes(BitConverter.GetBytes(d));
				
            // Modified to XOR-encrypt string content
			void WriteString(string str)
			{
				byte[] bytes = _luaEncoding.GetBytes(str);
                
                // Use a dynamic key based on string length (simple)
                byte key = (byte)(bytes.Length % 256); 
                
                bytes = SimpleXOREncrypt(bytes, key);
				
                // Write the original length + 1 (for null terminator, though it's now encrypted)
				WriteInt(bytes.Length + 1);
				WriteBytes(bytes);
				WriteByte(key); // Write the XOR key as the "null terminator"
			}

            // Modified to use obfuscated instructions and skip debug info
			void WriteChunk(Chunk chunk)
			{
				if (!string.IsNullOrEmpty(chunk.Name))
					WriteString(chunk.Name);
				else
					WriteInt(0);

				WriteInt(chunk.Line);
				WriteInt(chunk.LastLine);
				WriteByte(chunk.UpvalueCount);
				WriteByte(chunk.ParameterCount);
				WriteByte(chunk.VarargFlag);
				WriteByte(chunk.StackSize);
				
				chunk.UpdateMappings();
				
                // --- Instructions (Obfuscated OpCodes) ---
				WriteInt(chunk.Instructions.Count);
				foreach (var i in chunk.Instructions)
				{
					i.UpdateRegisters();
					
					int a = i.A;
					int b = i.B;
					int c = i.C;

					// 1. Get the obfuscated OpCode index
                    uint obfuscatedOpCode = _shuffledOpcodeMap[i.OpCode];

					uint result = 0;

                    // 2. Insert the obfuscated OpCode (6 bits)
					result |= obfuscatedOpCode;
                    
                    // 3. Insert A (8 bits, standard position)
					result |= ((uint)a << 6);

					switch (i.InstructionType)
					{
						case InstructionType.ABx:
							result |= ((uint)b << (6 + 8));
							break;
						
						case InstructionType.AsBx:
							// Apply bias, but use the new encoding.
							uint biasedB = (uint)(b + 131071);
							result |= (biasedB << (6 + 8));
							break;
						
						case InstructionType.ABC:
                            // C is at standard position
							result |= ((uint)c << (6 + 8));
                            // B is at standard position
							result |= ((uint)b << (6 + 8 + 9));
							break;
					}

                    // 4. Optionally XOR the instruction for an extra layer (dynamic key based on A)
                    // This makes the instruction stream look random.
                    result ^= (uint)(a * 0x7654321);

					WriteUInt(result);
				}

                // --- Constants (Encrypted Strings) ---
				WriteInt(chunk.Constants.Count);
				foreach (var constant in chunk.Constants)
				{
					switch (constant.Type)
					{
						case ConstantType.Nil:
							WriteByte(0);
							break;
							
						case ConstantType.Boolean:
							WriteByte(1);
							WriteByte((byte) ((bool) constant.Data ? 1 : 0));
							break;
						
						case ConstantType.Number:
                            // Numbers are usually left alone, but we'll change the type marker
							WriteByte(0xCA); // Custom marker for Number
							WriteDouble(constant.Data);
							break;
						
						case ConstantType.String:
							WriteByte(0xAB); // Custom marker for String
							WriteString((string) constant.Data); // Uses the XOR-encrypted string writer
							break;
                            
                        default:
                            WriteByte(0xCC); // Fallback marker for safety
                            break;
					}
				}
				
				WriteInt(chunk.Functions.Count);
				foreach (var sChunk in chunk.Functions)
					WriteChunk(sChunk);
				
                // --- Junk Debug Info ---
                // Write large, meaningless numbers to fill the debug info section
				WriteInt(0xDEADBEEF); // Junk line info count
				WriteInt(0xDEADBEEF); // Junk local list count
				WriteInt(0xDEADBEEF); // Junk upvalue list count
			}
			
            // --- Write Obfuscated Header ---
            WriteBytes(_magicBytes);        // Tampered Magic Number
			WriteByte(_customVersion);      // Tampered Version
			WriteByte(0);                   // Format Version
			WriteByte(_customEndianness);   // Tampered Endianness
			WriteByte(4);                   // Int Size
			WriteByte(4);                   // SizeT Size
			WriteByte(4);                   // Instruction Size
			WriteByte(8);                   // Number Size
			WriteByte(0);                   // Number Format

			WriteChunk(_chunk);

			return res.ToArray();
		}
	}
}
