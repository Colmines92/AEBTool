using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Encodings.Web;

if (args.Length == 0)
    return Commands.PrintUsage();

string inputFile = args[0];
string inputExt = Path.GetExtension(inputFile);

if (args.Length >= 1 && string.IsNullOrEmpty(inputExt))
    return Commands.Decrypt(inputFile, args.Length > 1 ? args[1] : null);

if (args.Length >= 1 && inputExt.Equals(".json", StringComparison.OrdinalIgnoreCase))
    return Commands.Encrypt(inputFile, args.Length > 1 ? args[1] : null);

return Commands.PrintUsage();

// ============================================================

internal static class XorCipher
{
    private const byte KeyEven = 0xFE;
    private const byte KeyOdd  = 0x80;

    public static byte[] Transform(ReadOnlySpan<byte> data)
    {
        var result = new byte[data.Length];
        for (int i = 0; i < result.Length; i++)
            result[i] = (byte)(data[i] ^ ((i & 1) == 0 ? KeyEven : KeyOdd));
        return result;
    }
}

internal sealed class SaveFile
{
    public const int HeaderSize = 4;

    public int PayloadSize { get; }
    public byte[] EncryptedPayload { get; }
    public int OriginalTotalSize { get; }

    private SaveFile(int payloadSize, byte[] encryptedPayload, int originalTotalSize)
    {
        PayloadSize = payloadSize;
        EncryptedPayload = encryptedPayload;
        OriginalTotalSize = originalTotalSize;
    }

    public static SaveFile Load(string path)
    {
        byte[] raw = File.ReadAllBytes(path);

        if (raw.Length < HeaderSize)
            throw new InvalidDataException($"File only has {raw.Length} bytes.");

        int size = BinaryPrimitives.ReadInt32LittleEndian(raw);

        if (size < 0 || (long)HeaderSize + size > raw.Length)
            throw new InvalidDataException(
                $"Header mismatch: Says payload has {size:N0} bytes but file has {raw.Length:N0}.");

        return new SaveFile(size, raw[HeaderSize..(HeaderSize + size)], raw.Length);
    }

    public static byte[] Assemble(byte[] encryptedPayload, byte[]? trailingBytes = null)
    {
        trailingBytes ??= Array.Empty<byte>();

        using var ms = new MemoryStream(HeaderSize + encryptedPayload.Length + trailingBytes.Length);

        Span<byte> header = stackalloc byte[HeaderSize];
        BinaryPrimitives.WriteInt32LittleEndian(header, encryptedPayload.Length);
        ms.Write(header);
        ms.Write(encryptedPayload);
        ms.Write(trailingBytes);

        return ms.ToArray();
    }
}

internal static class Commands
{
    private const int SystemData_Size = 50000;
    private const int UserData_Size = 943718;

    // ---------------- decrypt ----------------
    public static int Decrypt(string datPath, string? jsonPath)
	{
		try
		{
			jsonPath ??= Path.ChangeExtension(datPath, ".json");

			SaveFile file = SaveFile.Load(datPath);
			byte[] json = XorCipher.Transform(file.EncryptedPayload);

			if (json.Length == 0 || json[0] != (byte)'{')
				throw new InvalidDataException("Invalid file");

			using var doc = JsonDocument.Parse(json);
			var options = new JsonSerializerOptions
			{
				WriteIndented = true,
				Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
			};
			File.WriteAllText(jsonPath, JsonSerializer.Serialize(doc.RootElement, options));

			Console.WriteLine($"OK: {datPath} -> {jsonPath}");
			return 0;
		}
		catch (Exception ex) { return Fail(ex); }
	}

    // ---------------- encrypt ----------------
    public static int Encrypt(string jsonPath, string? datPath)
	{
		try
		{
			byte[] json = File.ReadAllBytes(jsonPath);

			if (json.Length >= 3 && json[0] == 0xEF && json[1] == 0xBB && json[2] == 0xBF)
				json = json[3..];

			using var doc = JsonDocument.Parse(json);
            bool isUserSave = doc.RootElement.TryGetProperty("info", out _);
            var options = new JsonSerializerOptions
			{
				Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
			};
			byte[] minified = JsonSerializer.SerializeToUtf8Bytes(doc.RootElement, options);
			byte[] encrypted = XorCipher.Transform(minified);

            int padding = (isUserSave ? UserData_Size : SystemData_Size) - encrypted.Length - 4;

            if (padding < 0)
                padding = 0;

            datPath ??= Path.ChangeExtension(jsonPath, "");

            File.WriteAllBytes(datPath, SaveFile.Assemble(encrypted, padding > 0 ? new byte[padding] : null));
			Console.WriteLine($"OK: {jsonPath} -> {datPath}");
			return 0;
		}
		catch (JsonException ex)
		{
			return Fail(new InvalidDataException($"Invalid JSON: {ex.Message}"));
		}
		catch (Exception ex) { return Fail(ex); }
	}

    public static int PrintUsage()
    {
        Console.WriteLine("Another Eden Begins Save decrypter/encrypter by Colmines92");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  AEBTool <input> [output.json]");
        Console.WriteLine("  AEBTool <input.json> [output]");
        return 1;
    }

    // ---------------- helpers ----------------

    private static int Fail(Exception ex)
    {
        Console.Error.WriteLine($"ERROR: {ex.Message}");
        return 1;
    }

    private static string Fmt(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement value))
            return "(ausente)";

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? "(null)",
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True   => "true",
            JsonValueKind.False  => "false",
            JsonValueKind.Null   => "null",
            _                    => value.GetRawText(),
        };
    }

    private static void DumpFlag(JsonElement element, string name, string indent = "")
    {
        if (element.TryGetProperty(name, out _))
            Console.WriteLine($"{indent}{name,-20} = {Fmt(element, name)}");
    }
}