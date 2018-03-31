using System;

using System.Text;

using System.IO;

using System.Threading;

using System.Collections.Generic;

using System.Net;
using System.Net.Sockets;

using System.Security.Cryptography;

namespace ProjectTServer {
	static class MainClass {
		static Socket server;
		static readonly List<Socket> clients = new List<Socket>();

		static Thread serverThread;
		static readonly List<Thread> clientThreads = new List<Thread>();

		public static void Main(string[] args) {
			var ipHostInfo = Dns.GetHostEntry(Dns.GetHostName());
			var ipAddress = ipHostInfo.AddressList[0];
			var localEndPoint = new IPEndPoint(ipAddress, 11000);

			server = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
			server.Bind(localEndPoint);
			server.Listen(10);

			serverThread = new Thread(ServerHandler);
			serverThread.Start();

			while (true) {
				Test();
				Console.ReadLine();
			}
		}

		static void Test() {
			var ipHostInfo = Dns.GetHostEntry(Dns.GetHostName());
			var ipAddress = ipHostInfo.AddressList[0];
			var remoteEndPoint = new IPEndPoint(ipAddress, 11000);

			var socket = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

			socket.Connect(remoteEndPoint);

			var hmacServerKey = ExchangeKey(socket);
			var hmacClientKey = ExchangeKey(socket);

			var aesServerKey = ExchangeKey(socket);
			var aesClientKey = ExchangeKey(socket);

			var iv = ExchangeKey(socket);
			var aesServerIv = new byte[16];
			var aesClientIv = new byte[16];
			Array.Copy(iv, 0, aesServerIv, 0, 16);
			Array.Copy(iv, 16, aesClientIv, 0, 16);

			var message = Encoding.UTF8.GetBytes("Hi from server.");
			var cipherText = Encrypt(aesServerKey, aesServerIv, message, 0, message.Length);
			Send(socket, hmacServerKey, cipherText, 0, cipherText.Length);

			var buffer = new byte[PayloadFieldMaxSize];
			int length = Receive(socket, hmacClientKey, buffer, 0);
			message = Decrypt(aesClientKey, aesClientIv, buffer, 0, length);
			Console.WriteLine(Encoding.UTF8.GetString(message));

			using (var rng = new RNGCryptoServiceProvider()) {
				message = new byte[4];
				rng.GetBytes(message);
				int answer = BitConverter.ToInt32(message, 0) + 1;

				cipherText = Encrypt(aesServerKey, aesServerIv, message, 0, message.Length);
				Send(socket, hmacServerKey, cipherText, 0, cipherText.Length);

				length = Receive(socket, hmacClientKey, buffer, 0);
				message = Decrypt(aesClientKey, aesClientIv, buffer, 0, length);

				if (BitConverter.ToInt32(message, 0) == answer) Console.WriteLine("Verified!");
			}

			socket.Shutdown(SocketShutdown.Both);
			socket.Close();
		}

		static void ServerHandler() {
			while (true) {
				Console.WriteLine("Waiting for a connection...");

				var client = server.Accept();
				clients.Add(client);

				var clientThread = new Thread(() => ClientHandler(client));
				clientThread.Start();
				clientThreads.Add(clientThread);
			}
		}
			
		const int LengthFieldSize = 4, PayloadFieldMaxSize = 1024, HmacFieldSize = 32;
		static void ClientHandler(Socket socket) {
			var hmacServerKey = ExchangeKey(socket);
			var hmacClientKey = ExchangeKey(socket);

			var aesServerKey = ExchangeKey(socket);
			var aesClientKey = ExchangeKey(socket);

			var iv = ExchangeKey(socket);
			var aesServerIv = new byte[16];
			var aesClientIv = new byte[16];
			Array.Copy(iv, 0, aesServerIv, 0, 16);
			Array.Copy(iv, 16, aesClientIv, 0, 16);

			var buffer = new byte[PayloadFieldMaxSize];
			int length = Receive(socket, hmacServerKey, buffer, 0);
			var message = Decrypt(aesServerKey, aesServerIv, buffer, 0, length);
			Console.WriteLine(Encoding.UTF8.GetString(message));

			message = Encoding.UTF8.GetBytes("Hi from client.");
			var cipherText = Encrypt(aesClientKey, aesClientIv, message, 0, message.Length);
			Send(socket, hmacClientKey, cipherText, 0, cipherText.Length);

			length = Receive(socket, hmacServerKey, buffer, 0);
			message = Decrypt(aesServerKey, aesServerIv, buffer, 0, length);

			message = BitConverter.GetBytes((Int32)(BitConverter.ToInt32(message, 0) + 1));
			cipherText = Encrypt(aesClientKey, aesClientIv, message, 0, message.Length);
			Send(socket, hmacClientKey, cipherText, 0, cipherText.Length);

			Console.WriteLine("Finish challenge");

			socket.Shutdown(SocketShutdown.Both);
			socket.Close();
		}

#region HamcKey

		static readonly byte[] HmacKey = {
			0xE6,
			0xAD,
			0xA4,
			0xE7,
			0x94,
			0x9F,
			0xE6,
			0x97,
			0xA0,
			0xE6,
			0x82,
			0x94,
			0xE5,
			0x85,
			0xA5,
			0xE4,
			0xB8,
			0x9C,
			0xE6,
			0x96,
			0xB9,
			0xEF,
			0xBC,
			0x8C,
			0xE6,
			0x9D,
			0xA5,
			0xE4,
			0xB8,
			0x96,
			0xE6,
			0x84,
			0xBF,
			0xE7,
			0x94,
			0x9F,
			0xE5,
			0xB9,
			0xBB,
			0xE6,
			0x83,
			0xB3,
			0xE4,
			0xB9,
			0xA1,
			0xE3,
			0x80,
			0x82,
			0xE4,
			0xB8,
			0x80,
			0xE4,
			0xB9,
			0xA1,
			0xE4,
			0xB8,
			0x80,
			0xE6,
			0xA2,
			0xA6,
			0xE5,
			0xB9,
			0xBD,
			0xE6
		};

#endregion

		/* field   size   type
		 * length  4      uint
		 * payload length bits
		 * hmac    32     sha256
		 */
		static int Send(Socket socket, byte[] key, byte[] payload, int offset, int length) {
			Console.WriteLine("\tsend...");
			Console.WriteLine("\t\tlength: {0}", length);

			SocketError error;
			var lengthBuffer = BitConverter.GetBytes((Int32)length);
			int sent = socket.Send(lengthBuffer, 0, LengthFieldSize, SocketFlags.None, out error);
			if (error != SocketError.Success) {
				Console.WriteLine("\t\terror: {0}", error);
				return -1;
			} else if (sent != LengthFieldSize) {
				Console.WriteLine("\t\terror: sent {0}, expecting {1}", sent, LengthFieldSize);
				return -1;
			}

			sent = socket.Send(payload, offset, length, SocketFlags.None, out error);
			if (error != SocketError.Success) {
				Console.WriteLine("\t\terror: {0}", error);
				return -1;
			} else if (sent != length) {
				Console.WriteLine("\t\terror: sent {0}, expecting {1}", sent, length);
				return -1;
			}

			using (var hasher = new HMACSHA256(key)) {
				var hash = hasher.ComputeHash(payload, offset, length);
				Console.WriteLine("\t\thash: {0}", BytesToString(hash));
				
				sent = socket.Send(hash, 0, HmacFieldSize, SocketFlags.None, out error);
				if (error != SocketError.Success) {
					Console.WriteLine("\t\terror: {0}", error);
					return -1;
				} else if (sent != HmacFieldSize) {
					Console.WriteLine("\t\terror: sent {0}, expecting {1}", sent, HmacFieldSize);
					return -1;
				}
			}

			Console.WriteLine("\tsent");
			return length;
		}

		static int Receive(Socket socket, byte[] key, byte[] payload, int offset) {
			Console.WriteLine("\treceive...");

			SocketError error;
			var lengthBuffer = new byte[LengthFieldSize];
			int received = socket.Receive(lengthBuffer, 0, LengthFieldSize, SocketFlags.None, out error);
			if (error != SocketError.Success) {
				Console.WriteLine("\t\terror: {0}", error);
				return -1;
			} else if (received != LengthFieldSize) {
				Console.WriteLine("\t\terror: received {0}, expecting {1}", received, LengthFieldSize);
				return -1;
			}

			int length = BitConverter.ToInt32(lengthBuffer, 0);
			Console.WriteLine("\t\tlength: {0}", length);
			if (length <= 0 || length > PayloadFieldMaxSize) {
				Console.WriteLine("\t\terror: invalid length");
				return -1;
			}

			received = socket.Receive(payload, offset, length, SocketFlags.None, out error);
			if (error != SocketError.Success) {
				Console.WriteLine("\t\terror: {0}", error);
				return -1;
			} else if (received != length) {
				Console.WriteLine("\t\terror: received {0}, expecting {1}", received, length);
				return -1;
			}

			var hmacBuffer = new byte[HmacFieldSize];
			received = socket.Receive(hmacBuffer, 0, HmacFieldSize, SocketFlags.None, out error);
			if (error != SocketError.Success) {
				Console.WriteLine("\t\terror: {0}", error);
				return -1;
			} else if (received != HmacFieldSize) {
				Console.WriteLine("\t\terror: received {0}, expecting {1}", received, HmacFieldSize);
				return -1;
			}
			Console.WriteLine("\t\thmac: {0}", BytesToString(hmacBuffer));

			using (var hasher = new HMACSHA256(key)) {
				var hash = hasher.ComputeHash(payload, 0, length);
				Console.WriteLine("\t\thash: {0}", BytesToString(hash));

				bool isEqual = true;
				for (int i = 0; i < HmacFieldSize; i++) {
					if (hmacBuffer[i] != hash[i]) {
						isEqual = false;
						break;
					}
				}
				if (!isEqual) {
					Console.WriteLine("\t\thmac incorrect");
					return -1;
				}
			}

			Console.WriteLine("\treceived");
			return length;
		}

		static byte[] ExchangeKey(Socket socket) {
			Console.WriteLine("exchange key...");

			using (var dh = new ECDiffieHellmanCng()) {
				dh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
				dh.HashAlgorithm = CngAlgorithm.Sha256;

				var publicKey = dh.PublicKey.ToByteArray();
				Console.WriteLine("\tpublic key: {0}", BytesToString(publicKey));
				Send(socket, HmacKey, publicKey, 0, publicKey.Length);

				var otherKey = new byte[publicKey.Length];
				Receive(socket, HmacKey, otherKey, 0);
				Console.WriteLine("\tother key: {0}", BytesToString(otherKey));

				var key = dh.DeriveKeyMaterial(CngKey.Import(otherKey, CngKeyBlobFormat.EccPublicBlob));
				Console.WriteLine("key exchanged: {0}", BytesToString(key));

				return key;
			}
		}

		static byte[] Encrypt(byte[] key, byte[] iv, byte[] message, int offset, int length) {
			using (var aes = new AesCryptoServiceProvider()) {
				aes.Key = key;
				aes.IV = iv;

				using (var cipherText = new MemoryStream()) using (var cryptoStream = new CryptoStream(cipherText, aes.CreateEncryptor(), CryptoStreamMode.Write)) {

					cryptoStream.Write(message, offset, length);
					cryptoStream.Close();

					return cipherText.ToArray();
				}
			}
		}

		static byte[] Decrypt(byte[] key, byte[] iv, byte[] cipherText, int offset, int length) {
			using (var aes = new AesCryptoServiceProvider()) {
				aes.Key = key;
				aes.IV = iv;

				using (var message = new MemoryStream()) using (var cryptoStream = new CryptoStream(message, aes.CreateDecryptor(), CryptoStreamMode.Write)) {

					cryptoStream.Write(cipherText, offset, length);
					cryptoStream.Close();

					return message.ToArray();
				}
			}
		}

		static string BytesToString(byte[] bytes) {
			const int previewLength = 16;
			return bytes.Length < previewLength ? string.Format("{0} ({1})", BitConverter.ToString(bytes), bytes.Length) : string.Format("{0}... ({1})", BitConverter.ToString(bytes, 0, previewLength), bytes.Length);
		}
	}
}
