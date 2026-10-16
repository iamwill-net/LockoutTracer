// Generates src\app.ico (16-256 px): padlock + magnifier on a dark tile, matching the app theme.
// Build & run:  csc /r:System.Drawing.dll MakeIcon.cs && MakeIcon.exe ..\src\app.ico [previewDir]
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

static class MakeIcon
{
    static readonly Color Tile = Color.FromArgb(37, 37, 38);
    static readonly Color TileEdge = Color.FromArgb(70, 70, 78);
    static readonly Color Shackle = Color.FromArgb(220, 220, 225);
    static readonly Color Body = Color.FromArgb(232, 112, 92);
    static readonly Color Lens = Color.FromArgb(117, 190, 255);

    static GraphicsPath RoundRect(RectangleF r, float rad)
    {
        var p = new GraphicsPath();
        float d = rad * 2;
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    static Bitmap Draw(int s)
    {
        var bmp = new Bitmap(s, s, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.Clear(Color.Transparent);
            bool small = s < 32;
            float inset = small ? 0 : s * 0.03f;
            using (var tile = RoundRect(new RectangleF(inset, inset, s - 2 * inset - 1, s - 2 * inset - 1), s * 0.2f))
            {
                using (var b = new SolidBrush(Tile)) g.FillPath(b, tile);
                using (var p = new Pen(TileEdge, Math.Max(1f, s / 64f))) g.DrawPath(p, tile);
            }

            // Padlock in unit space, shifted up-left to make room for the magnifier at larger sizes.
            float k = small ? 1.0f : 0.86f, ox = small ? 0 : -0.07f, oy = small ? 0 : -0.04f;
            Func<float, float> X = v => ((v - 0.5f) * k + 0.5f + ox) * s;
            Func<float, float> Y = v => ((v - 0.5f) * k + 0.5f + oy) * s;
            Func<float, float> L = v => v * k * s;

            using (var p = new Pen(Shackle, L(small ? 0.12f : 0.09f)) { StartCap = LineCap.Flat, EndCap = LineCap.Flat })
            {
                var path = new GraphicsPath();
                path.AddLine(X(0.33f), Y(0.48f), X(0.33f), Y(0.36f));
                path.AddArc(X(0.33f), Y(0.17f), L(0.34f), L(0.38f), 180, 180);
                path.AddLine(X(0.67f), Y(0.36f), X(0.67f), Y(0.48f));
                g.DrawPath(p, path);
            }
            using (var body = RoundRect(new RectangleF(X(0.20f), Y(0.44f), L(0.60f), L(0.42f)), L(0.07f)))
            using (var b = new SolidBrush(Body)) g.FillPath(b, body);
            using (var b = new SolidBrush(Tile))
            {
                float r = L(small ? 0.08f : 0.06f);
                g.FillEllipse(b, X(0.5f) - r, Y(0.61f) - r, 2 * r, 2 * r);
                if (!small) g.FillRectangle(b, X(0.5f) - L(0.025f), Y(0.61f), L(0.05f), L(0.13f));
            }

            if (!small)
            {
                float cx = s * 0.68f, cy = s * 0.68f, r = s * 0.155f;
                using (var cut = new Pen(Tile, s * 0.14f) { StartCap = LineCap.Round, EndCap = LineCap.Round })
                {
                    g.DrawLine(cut, cx + r * 0.75f, cy + r * 0.75f, s * 0.86f, s * 0.86f);
                    g.DrawEllipse(new Pen(Tile, s * 0.06f), cx - r - s * 0.03f, cy - r - s * 0.03f, 2 * r + s * 0.06f, 2 * r + s * 0.06f);
                }
                using (var b = new SolidBrush(Color.FromArgb(230, 30, 30, 30))) g.FillEllipse(b, cx - r, cy - r, 2 * r, 2 * r);
                using (var p = new Pen(Lens, s * 0.065f)) g.DrawEllipse(p, cx - r, cy - r, 2 * r, 2 * r);
                using (var p = new Pen(Lens, s * 0.085f) { StartCap = LineCap.Round, EndCap = LineCap.Round })
                    g.DrawLine(p, cx + r * 0.78f, cy + r * 0.78f, s * 0.86f, s * 0.86f);
            }
        }
        return bmp;
    }

    // Classic DIB icon entry (works everywhere, incl. the Win32 resource compiler).
    static byte[] Dib(Bitmap bmp)
    {
        int s = bmp.Width;
        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(40); w.Write(s); w.Write(s * 2); w.Write((short)1); w.Write((short)32);
        w.Write(0); w.Write(0); w.Write(0); w.Write(0); w.Write(0); w.Write(0);
        for (int y = s - 1; y >= 0; y--)
            for (int x = 0; x < s; x++)
            {
                var c = bmp.GetPixel(x, y);
                w.Write(c.B); w.Write(c.G); w.Write(c.R); w.Write(c.A);
            }
        int maskRow = ((s + 31) / 32) * 4;
        w.Write(new byte[maskRow * s]);   // AND mask unused with 32bpp alpha
        return ms.ToArray();
    }

    static byte[] Png(Bitmap bmp)
    {
        var ms = new MemoryStream();
        bmp.Save(ms, ImageFormat.Png);
        return ms.ToArray();
    }

    static void Main(string[] args)
    {
        int[] sizes = { 16, 20, 24, 32, 40, 48, 64, 128, 256 };
        var images = new List<byte[]>();
        foreach (int s in sizes)
            using (var bmp = Draw(s))
            {
                images.Add(s == 256 ? Png(bmp) : Dib(bmp));
                if (args.Length > 1) bmp.Save(Path.Combine(args[1], "icon" + s + ".png"), ImageFormat.Png);
            }

        using (var w = new BinaryWriter(File.Create(args[0])))
        {
            w.Write((short)0); w.Write((short)1); w.Write((short)sizes.Length);
            int offset = 6 + 16 * sizes.Length;
            for (int i = 0; i < sizes.Length; i++)
            {
                w.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
                w.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
                w.Write((byte)0); w.Write((byte)0);
                w.Write((short)1); w.Write((short)32);
                w.Write(images[i].Length); w.Write(offset);
                offset += images[i].Length;
            }
            foreach (var img in images) w.Write(img);
        }
        Console.WriteLine("Wrote " + args[0]);
    }
}
