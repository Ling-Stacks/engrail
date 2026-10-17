//
// Demo.cs -- C# binding demo: full vendor issue -> customer activate ->
// startup verify cycle, plus SM2/SM3/Ed25519 primitives.
//
// Run via build.sh (dotnet) or:  csc Engrail.cs Demo.cs && mono Demo.exe
//

using System;
using Engrail;

static class Demo
{
    static int failed = 0;

    static void Ok(string name, bool cond)
    {
        Console.WriteLine($"  [{(cond ? "PASS" : "FAIL")}] {name}");
        if (!cond) failed++;
    }

    static int Main()
    {
        Console.WriteLine("engrail-csharp demo");

        /* vendor: generate a keypair once */
        var (pub, priv) = Crypto.Ed25519Keypair();
        var dsalt = new byte[32];
        new Random(1234).NextBytes(dsalt); // demo only: use real entropy

        /* customer: machine code + activate */
        var act = new Activation(HexEncode(pub), HexEncode(dsalt), 42);
        var machineCode = act.MachineCode();
        Console.WriteLine($"  machine code: {machineCode}");
        Ok("machine code format",
           machineCode.Length == 32 + 1 && machineCode[16] == '-');

        /* vendor: issue a 365-day license bound to this machine */
        var hexFp = machineCode.Replace("-", "");
        var fpBytes = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            fpBytes[i] = Convert.ToByte(hexFp.Substring(i * 2, 2), 16);
        }
        var code = Vendor.MakeLicense(priv, 42, fpBytes, 27340, false, 0x0003);
        Console.WriteLine($"  license: {code.Substring(0, 26)}...");

        var (st, info) = act.VerifyCode(code);
        Ok("verify code ok", st == Status.Ok && info.Features == 0x0003);
        Ok("activate persists state", act.Activate(code, "demo_cs.act") == Status.Ok);
        Ok("verify saved ok", act.VerifySaved("demo_cs.act") == Status.Ok);
        Ok("wrong product rejected",
           act2Rejects(code, pub, dsalt));

        /* crypto primitives straight from the same library */
        Ok("SM3('abc') GB/T 32905",
           HexEncode(Crypto.Sm3(System.Text.Encoding.ASCII.GetBytes("abc")))
           == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

        var (spub, spriv) = Crypto.Sm2Keypair();
        var msg = System.Text.Encoding.UTF8.GetBytes("SM2 from C#");
        var sig2 = Crypto.Sm2Sign(msg, spriv);
        Ok("SM2 sign/verify", Crypto.Sm2Verify(sig2, msg, spub));
        var ct = Crypto.Sm2Encrypt(spub, msg);
        var pt = Crypto.Sm2Decrypt(ct, spriv);
        Ok("SM2 encrypt/decrypt round-trip",
           pt != null && HexEncode(pt) == HexEncode(msg));

        var sig1 = Crypto.Ed25519Sign(msg, priv);
        Ok("Ed25519 sign/verify", Crypto.Ed25519Verify(sig1, msg, pub));
        sig1[0] ^= 1;
        Ok("Ed25519 tamper rejected", !Crypto.Ed25519Verify(sig1, msg, pub));

        if (failed == 0)
        {
            Console.WriteLine("engrail-csharp: ALL DEMO CHECKS PASSED");
            return 0;
        }
        Console.WriteLine($"engrail-csharp: {failed} CHECK(S) FAILED");
        return 1;
    }

    static bool act2Rejects(string code, byte[] pub, byte[] dsalt)
    {
        var other = new Activation(HexEncode(pub), HexEncode(dsalt), 43);
        return other.VerifyCode(code).status == Status.ProductMismatch;
    }

    static string HexEncode(byte[] b)
    {
        var sb = new System.Text.StringBuilder(b.Length * 2);
        foreach (var x in b) sb.Append(x.ToString("x2"));
        return sb.ToString();
    }
}
