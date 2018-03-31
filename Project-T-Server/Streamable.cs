using System;
using System.IO;

namespace ProjectTServer {
	public abstract class Streamable {
		protected static class Assert {
			public static void Equal(Int32 a, Int32 b) {
				if (a != b) throw new InvalidProgramException(string.Format("{0} != {1}", a, b));
			}

			public static void Equal(UInt32 a, UInt32 b) {
				if (a != b) throw new InvalidProgramException(string.Format("{0} != {1}", a, b));
			}
		}

		protected readonly Stream _stream;

		protected Streamable(Stream stream) {
			_stream = stream;
		}

		public abstract void Serialize(Stream stream);

		protected bool IsEnd(Stream stream) {
			return stream.Position >= _stream.Length;
		}

		protected void Skip(Stream stream, int val) {
			stream.Position += val;
		}

		protected Char ReadChar() {
			return (char)_stream.ReadByte();
		}
			
		protected Byte ReadByte() {
			return (byte)_stream.ReadByte();
		}

		protected void WriteByte(Stream stream, Byte value) {
			stream.WriteByte(value);
		}

		protected string ReadString(int count) {
			var buffer = new byte[count];
			_stream.Read(buffer, 0, count);
			return System.Text.Encoding.UTF8.GetString(buffer).Trim();
		}

		protected void WriteString(Stream stream, string str) {
			var buffer = System.Text.Encoding.UTF8.GetBytes(str.Trim());
			stream.Write(buffer, 0, buffer.Length);
		}

		protected Int16 ReadInt16() {
			return (short)(_stream.ReadByte() | (sbyte)_stream.ReadByte() << 8);
		}

		protected void WriteInt16(Stream stream, Int16 value) {
			stream.WriteByte((byte)(value & 0xFF));
			stream.WriteByte((byte)((value >> 8) & 0xFF));
		}

		protected Int32 ReadInt32() {
			return _stream.ReadByte() | _stream.ReadByte() << 8 | _stream.ReadByte() << 16 | (sbyte)_stream.ReadByte() << 24;
		}

		protected void WriteInt32(Stream stream, Int32 value) {
			stream.WriteByte((byte)(value & 0xFF));
			stream.WriteByte((byte)((value >> 8) & 0xFF));
			stream.WriteByte((byte)((value >> 16) & 0xFF));
			stream.WriteByte((byte)((value >> 24) & 0xFF));
		}

		protected UInt16 ReadUInt16() {
			return (ushort)(_stream.ReadByte() | _stream.ReadByte() << 8);
		}

		protected void WriteUInt16(Stream stream, UInt16 value) {
			stream.WriteByte((byte)(value & 0xFF));
			stream.WriteByte((byte)((value >> 8) & 0xFF));
		}

		protected UInt32 ReadUInt32() {
			return (uint)(_stream.ReadByte() | _stream.ReadByte() << 8 | _stream.ReadByte() << 16 | _stream.ReadByte() << 24);
		}

		protected void WriteUInt32(Stream stream, UInt32 value) {
			stream.WriteByte((byte)(value & 0xFF));
			stream.WriteByte((byte)((value >> 8) & 0xFF));
			stream.WriteByte((byte)((value >> 16) & 0xFF));
			stream.WriteByte((byte)((value >> 24) & 0xFF));
		}
	}
}

