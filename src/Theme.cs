using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace LockoutTracer
{
    static class Theme
    {
        public static readonly Color Back = Color.FromArgb(30, 30, 30);       // window / chrome
        public static readonly Color Surface = Color.FromArgb(37, 37, 38);    // grids, text areas
        public static readonly Color AltRow = Color.FromArgb(43, 43, 45);
        public static readonly Color Raised = Color.FromArgb(51, 51, 55);     // inputs, buttons, headers
        public static readonly Color Hover = Color.FromArgb(62, 62, 66);
        public static readonly Color Border = Color.FromArgb(67, 67, 74);
        public static readonly Color Text = Color.FromArgb(230, 230, 230);
        public static readonly Color Muted = Color.FromArgb(150, 150, 155);
        public static readonly Color Accent = Color.FromArgb(0, 122, 204);
        public static readonly Color Selection = Color.FromArgb(9, 71, 113);
        public static readonly Color Red = Color.FromArgb(244, 135, 113);
        public static readonly Color Green = Color.FromArgb(137, 209, 133);
        public static readonly Color Amber = Color.FromArgb(229, 192, 123);
        public static readonly Color Blue = Color.FromArgb(117, 190, 255);
        public static readonly Color LockRow = Color.FromArgb(78, 36, 40);
        public static readonly Color UnlockRow = Color.FromArgb(30, 62, 40);
        public static readonly Color WarnRow = Color.FromArgb(74, 62, 26);

        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        static extern int SetWindowTheme(IntPtr hwnd, string appName, string idList);

        // Windows 10 1809+/Server 2019+; silently does nothing on older builds.
        public static void DarkTitleBar(Form f)
        {
            try
            {
                int on = 1;
                if (DwmSetWindowAttribute(f.Handle, 20, ref on, 4) != 0) DwmSetWindowAttribute(f.Handle, 19, ref on, 4);
            }
            catch { }
        }

        public static void DarkScrollbars(Control c)
        {
            try { SetWindowTheme(c.Handle, "DarkMode_Explorer", null); } catch { }
            foreach (Control child in c.Controls)
                if (child is ScrollBar) { try { SetWindowTheme(child.Handle, "DarkMode_Explorer", null); } catch { } }
        }

        public static void Style(Button b)
        {
            b.FlatStyle = FlatStyle.Flat;
            b.UseVisualStyleBackColor = false;
            b.BackColor = Raised;
            b.ForeColor = Text;
            b.FlatAppearance.BorderColor = Border;
            b.FlatAppearance.MouseOverBackColor = Hover;
            b.FlatAppearance.MouseDownBackColor = Selection;
            b.EnabledChanged += (s, e) => b.ForeColor = b.Enabled ? Text : Muted;
        }

        public static void Primary(Button b)
        {
            Style(b);
            b.BackColor = Accent;
            b.ForeColor = Color.White;
            b.FlatAppearance.BorderColor = Accent;
            b.FlatAppearance.MouseOverBackColor = Color.FromArgb(28, 151, 234);
            b.EnabledChanged += (s, e) => b.BackColor = b.Enabled ? Accent : Raised;
        }

        public static void Style(CheckBox c)
        {
            c.FlatStyle = FlatStyle.Flat;
            c.FlatAppearance.BorderColor = Muted;
            c.FlatAppearance.CheckedBackColor = Raised;
            c.ForeColor = Text;
        }

        public static void Style(DataGridView g)
        {
            g.BackgroundColor = Surface;
            g.GridColor = Border;
            g.BorderStyle = BorderStyle.None;
            g.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            g.EnableHeadersVisualStyles = false;
            g.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.Single;
            g.ColumnHeadersDefaultCellStyle.BackColor = Raised;
            g.ColumnHeadersDefaultCellStyle.ForeColor = Text;
            g.ColumnHeadersDefaultCellStyle.SelectionBackColor = Raised;
            g.ColumnHeadersDefaultCellStyle.SelectionForeColor = Text;
            g.DefaultCellStyle.BackColor = Surface;
            g.DefaultCellStyle.ForeColor = Text;
            g.DefaultCellStyle.SelectionBackColor = Selection;
            g.DefaultCellStyle.SelectionForeColor = Color.White;
            g.AlternatingRowsDefaultCellStyle.BackColor = AltRow;
            g.HandleCreated += (s, e) => DarkScrollbars(g);
        }

        public static void Style(TextBoxBase t)
        {
            t.BackColor = Surface;
            t.ForeColor = Text;
            t.HandleCreated += (s, e) => DarkScrollbars(t);
        }
    }

    // TabControl can't be fully dark-painted, so this is a minimal replacement: a strip of flat buttons over a body panel.
    class DarkTab
    {
        public Button Header;
        public Control Body;
        public string Text { get { return Header.Text; } set { Header.Text = value; } }
    }

    class DarkTabs : Panel
    {
        readonly FlowLayoutPanel strip;
        readonly Panel body;
        readonly List<DarkTab> tabs = new List<DarkTab>();
        DarkTab selected;

        public DarkTabs()
        {
            Dock = DockStyle.Fill;
            BackColor = Theme.Back;
            body = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface };
            strip = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Padding = new Padding(6, 0, 0, 0), BackColor = Theme.Back };
            var line = new Panel { Dock = DockStyle.Top, Height = 2, BackColor = Theme.Accent };
            Controls.Add(body);
            Controls.Add(line);
            Controls.Add(strip);
        }

        public DarkTab Add(string title, Control content)
        {
            var b = new Button { Text = title, AutoSize = true, Margin = new Padding(0, 2, 2, 0), Padding = new Padding(10, 3, 10, 3), TabStop = false };
            b.FlatStyle = FlatStyle.Flat;
            b.UseVisualStyleBackColor = false;
            b.FlatAppearance.BorderSize = 0;
            b.FlatAppearance.MouseOverBackColor = Theme.Hover;
            content.Dock = DockStyle.Fill;
            content.Visible = false;
            body.Controls.Add(content);
            strip.Controls.Add(b);
            var tab = new DarkTab { Header = b, Body = content };
            tabs.Add(tab);
            b.Click += (s, e) => Select(tab);
            if (selected == null) Select(tab); else PaintTab(tab, false);
            return tab;
        }

        public void Select(DarkTab tab)
        {
            selected = tab;
            foreach (var t in tabs)
            {
                t.Body.Visible = t == tab;
                PaintTab(t, t == tab);
            }
        }

        public DarkTab Selected { get { return selected; } }

        static void PaintTab(DarkTab t, bool on)
        {
            t.Header.BackColor = on ? Theme.Accent : Theme.Back;
            t.Header.ForeColor = on ? Color.White : Theme.Muted;
            t.Header.FlatAppearance.MouseOverBackColor = on ? Theme.Accent : Theme.Hover;
        }
    }

    class DarkRenderer : ToolStripProfessionalRenderer
    {
        public DarkRenderer() : base(new DarkColors()) { RoundedEdges = false; }

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = e.Item.Enabled ? Theme.Text : Theme.Muted;
            base.OnRenderItemText(e);
        }
    }

    class DarkColors : ProfessionalColorTable
    {
        public override Color StatusStripGradientBegin { get { return Theme.Raised; } }
        public override Color StatusStripGradientEnd { get { return Theme.Raised; } }
        public override Color ToolStripDropDownBackground { get { return Theme.Raised; } }
        public override Color ImageMarginGradientBegin { get { return Theme.Raised; } }
        public override Color ImageMarginGradientMiddle { get { return Theme.Raised; } }
        public override Color ImageMarginGradientEnd { get { return Theme.Raised; } }
        public override Color MenuBorder { get { return Theme.Border; } }
        public override Color MenuItemBorder { get { return Theme.Accent; } }
        public override Color MenuItemSelected { get { return Theme.Selection; } }
        public override Color MenuItemSelectedGradientBegin { get { return Theme.Selection; } }
        public override Color MenuItemSelectedGradientEnd { get { return Theme.Selection; } }
        public override Color SeparatorDark { get { return Theme.Border; } }
        public override Color SeparatorLight { get { return Theme.Border; } }
    }
}
