using System;
using System.Collections.Generic;
using System.Data;
using System.DirectoryServices;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("Lockout Tracer")]
[assembly: System.Reflection.AssemblyProduct("Lockout Tracer")]
[assembly: System.Reflection.AssemblyVersion("1.0.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.0.0.0")]

namespace LockoutTracer
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(args.Length > 0 ? args[0] : null));
        }
    }

    class MainForm : Form
    {
        TextBox txtUser;
        NumericUpDown numHours;
        CheckBox chkAll, chkDns;
        Button btnRun, btnUnlock, btnExport;
        DarkTabs tabs;
        DarkTab tabSummary, tabSources, tabEvents, tabDcs;
        RichTextBox rtbSummary;
        DataGridView gridSources, gridEvents, gridDcs;
        TextBox txtDetail, txtSourceDetail;
        ToolStripStatusLabel lblStatus;
        ToolStripProgressBar prog;

        ScanResult last;
        DataTable evTable, srcTable, dcTable;
        string autoRunUser;

        public MainForm(string user)
        {
            autoRunUser = user;
            SuspendLayout();
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Text = "Lockout Tracer - " + Environment.MachineName;
            Font = new Font("Segoe UI", 9F);
            Size = new Size(1280, 800);
            MinimumSize = new Size(900, 500);
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Theme.Back;
            ForeColor = Theme.Text;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            // --- top bar
            var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(6, 8, 6, 8), WrapContents = true };
            top.Controls.Add(new Label { Text = "User:", AutoSize = true, Margin = new Padding(3, 7, 0, 0) });
            txtUser = new TextBox { Width = 220, Margin = new Padding(3, 4, 12, 0), BorderStyle = BorderStyle.FixedSingle, BackColor = Theme.Raised, ForeColor = Theme.Text };
            top.Controls.Add(txtUser);
            top.Controls.Add(new Label { Text = "Look back (hours):", AutoSize = true, Margin = new Padding(3, 7, 0, 0) });
            numHours = new NumericUpDown { Minimum = 1, Maximum = 2160, Value = 24, Width = 60, Margin = new Padding(3, 4, 12, 0), BorderStyle = BorderStyle.FixedSingle, BackColor = Theme.Raised, ForeColor = Theme.Text };
            top.Controls.Add(numHours);
            chkAll = new CheckBox { Text = "All DCs", Checked = true, AutoSize = true, Margin = new Padding(3, 6, 6, 0) };
            chkDns = new CheckBox { Text = "Resolve IPs", Checked = true, AutoSize = true, Margin = new Padding(3, 6, 12, 0) };
            top.Controls.Add(chkAll);
            top.Controls.Add(chkDns);
            btnRun = new Button { Text = "Trace lockout", AutoSize = true, Margin = new Padding(3, 2, 3, 0), Padding = new Padding(8, 2, 8, 2) };
            btnUnlock = new Button { Text = "Unlock account...", AutoSize = true, Enabled = false, Margin = new Padding(3, 2, 3, 0), Padding = new Padding(4, 2, 4, 2) };
            btnExport = new Button { Text = "Export...", AutoSize = true, Enabled = false, Margin = new Padding(3, 2, 3, 0), Padding = new Padding(4, 2, 4, 2) };
            top.Controls.Add(btnRun);
            top.Controls.Add(btnUnlock);
            top.Controls.Add(btnExport);
            Theme.Style(chkAll);
            Theme.Style(chkDns);
            Theme.Primary(btnRun);
            Theme.Style(btnUnlock);
            Theme.Style(btnExport);
            btnUnlock.ForeColor = btnExport.ForeColor = Theme.Muted;
            var tip = new ToolTip();
            tip.SetToolTip(txtUser, "sAMAccountName, DOMAIN\\user or UPN");
            tip.SetToolTip(chkAll, "Read the Security log on every DC (bad-password events land on whichever DC authenticated the user). Unticked: PDC + this machine only.");
            tip.SetToolTip(chkDns, "Reverse-DNS the source IPs to machine names");

            // --- tabs
            tabs = new DarkTabs();
            rtbSummary = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = new Font("Segoe UI", 10F), DetectUrls = false };
            Theme.Style(rtbSummary);
            var summaryPad = new Panel { Padding = new Padding(12, 10, 4, 4), BackColor = Theme.Surface };
            summaryPad.Controls.Add(rtbSummary);
            tabSummary = tabs.Add("Summary", summaryPad);

            gridSources = MakeGrid();
            txtSourceDetail = MakeDetailBox();
            tabSources = tabs.Add("Likely sources", Split(gridSources, txtSourceDetail, 430));

            gridEvents = MakeGrid();
            txtDetail = MakeDetailBox();
            tabEvents = tabs.Add("Events", Split(gridEvents, txtDetail, 430));

            gridDcs = MakeGrid();
            tabDcs = tabs.Add("Domain controllers", gridDcs);

            // --- status
            var status = new StatusStrip { Renderer = new DarkRenderer(), BackColor = Theme.Raised, ForeColor = Theme.Text, SizingGrip = false };
            lblStatus = new ToolStripStatusLabel("Enter a user name and click Trace lockout.") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
            prog = new ToolStripProgressBar { Style = ProgressBarStyle.Marquee, Visible = false, Width = 150 };
            status.Items.Add(lblStatus);
            status.Items.Add(prog);

            Controls.Add(tabs);
            Controls.Add(top);
            Controls.Add(status);
            AcceptButton = btnRun;
            ResumeLayout(false);
            PerformLayout();

            btnRun.Click += (s, e) => StartTrace();
            btnUnlock.Click += (s, e) => Unlock();
            btnExport.Click += (s, e) => Export();
            gridEvents.SelectionChanged += (s, e) => ShowEventDetail();
            gridSources.SelectionChanged += (s, e) => ShowSourceDetail();
            gridEvents.CellFormatting += GridEvents_CellFormatting;
            gridDcs.CellFormatting += GridDcs_CellFormatting;
            gridSources.CellFormatting += GridSources_CellFormatting;
            gridSources.CellDoubleClick += (s, e) => JumpToSourceEvents();

            WriteIntro();
            HandleCreated += (s, e) => Theme.DarkTitleBar(this);
            Shown += (s, e) =>
            {
                if (!string.IsNullOrEmpty(autoRunUser)) { txtUser.Text = autoRunUser; StartTrace(); }
                else txtUser.Focus();
            };
        }

        static DataGridView MakeGrid()
        {
            var g = new DataGridView
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                AllowUserToResizeRows = false,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                MultiSelect = true,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None,
                ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableAlwaysIncludeHeaderText,
            };
            g.DefaultCellStyle.WrapMode = DataGridViewTriState.False;
            Theme.Style(g);
            return g;
        }

        static TextBox MakeDetailBox()
        {
            var t = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Font = new Font("Consolas", 9F), BorderStyle = BorderStyle.None };
            Theme.Style(t);
            return t;
        }

        static SplitContainer Split(Control topCtl, Control bottomCtl, int dist)
        {
            var sc = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = Theme.Border, SplitterWidth = 5 };
            sc.Panel1.BackColor = Theme.Surface;
            sc.Panel2.BackColor = Theme.Surface;
            sc.Panel1.Controls.Add(topCtl);
            sc.Panel2.Controls.Add(bottomCtl);
            sc.HandleCreated += (s, e) => { try { sc.SplitterDistance = Math.Max(100, Math.Min(dist, sc.Height - 120)); } catch { } };
            return sc;
        }

        // ------------------------------------------------------------ running

        void SetBusy(bool busy)
        {
            btnRun.Enabled = !busy;
            txtUser.Enabled = !busy;
            numHours.Enabled = !busy;
            chkAll.Enabled = !busy;
            chkDns.Enabled = !busy;
            btnUnlock.Enabled = !busy && last != null;
            btnExport.Enabled = !busy && last != null;
            prog.Visible = busy;
            UseWaitCursor = busy;
        }

        void Status(string s)
        {
            if (IsDisposed || !IsHandleCreated) return;
            BeginInvoke((Action)(() => lblStatus.Text = s));
        }

        void StartTrace()
        {
            string user = txtUser.Text.Trim();
            if (user.Length == 0) { txtUser.Focus(); return; }
            int hours = (int)numHours.Value;
            bool all = chkAll.Checked, dns = chkDns.Checked;
            SetBusy(true);
            Task.Factory.StartNew(() => Engine.Run(user, hours, all, dns, Status))
                .ContinueWith(t =>
                {
                    if (t.IsFaulted)
                    {
                        var ex = t.Exception.GetBaseException();
                        lblStatus.Text = "Failed: " + ex.Message.Split('\n')[0];
                        SetBusy(false);
                        MessageBox.Show(this, ex.Message, "Lockout Tracer", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                    last = t.Result;
                    ShowResult(last);
                    SetBusy(false);
                }, TaskScheduler.FromCurrentSynchronizationContext());
        }

        void ShowResult(ScanResult r)
        {
            WriteSummary(r);
            FillSources(r);
            FillEvents(r);
            FillDcs(r);
            tabEvents.Text = "Events (" + r.Events.Count + ")";
            tabSources.Text = "Likely sources (" + r.Sources.Count + ")";
            int bad = r.Dcs.Count(d => d.EventError != null || d.LdapError != null);
            tabDcs.Text = "Domain controllers (" + r.Dcs.Count + (bad > 0 ? ", " + bad + " with errors" : "") + ")";
            lblStatus.Text = string.Format("{0}: {1} events from {2} DC(s) in the last {3} h. {4}",
                r.User.Sam, r.Events.Count, r.Dcs.Count, r.Hours, r.Warnings.Count > 0 ? r.Warnings.Count + " warning(s) - see Summary." : "");
            tabs.Select(tabSummary);
        }

        // ------------------------------------------------------------ summary

        void WriteIntro()
        {
            rtbSummary.Clear();
            H("Lockout Tracer");
            P("Type a user name and click Trace lockout. The tool will:");
            P("  • read the account's lock state, bad-password counts and lockout policy from AD (every DC — badPwdCount isn't replicated)");
            P("  • search the Security log on the DCs for lockouts (4740), unlocks (4767), failed logons (4625), Kerberos failures (4771/4768) and NTLM failures (4776)");
            P("  • group the failures by source machine / IP and suggest what is probably sending the bad password");
            P("");
            P("Run it on a DC as a Domain Admin (it asks for elevation). Reading other DCs' logs needs the 'Remote Event Log Management' firewall rule on them.", Theme.Muted);
            P("Tip: you can also pass the user on the command line:  LockoutTracer.exe jsmith", Theme.Muted);
        }

        void WriteSummary(ScanResult r)
        {
            var u = r.User;
            rtbSummary.Clear();

            H((u.DisplayName.Length > 0 ? u.DisplayName + "  (" + u.Sam + ")" : u.Sam));
            P(u.Dn, Theme.Muted);
            if (u.Description.Length > 0) P(u.Description, Theme.Muted);
            P("");

            bool locked = IsLocked(u);
            if (locked)
            {
                string until;
                if (u.Duration.HasValue && (u.Duration.Value == 0 || u.Duration.Value == long.MinValue)) until = "stays locked until an admin unlocks it";
                else if (u.Duration.HasValue && u.LockoutTime.HasValue) until = "auto-unlocks at " + Fmt.Dt(u.LockoutTime.Value.AddTicks(Math.Abs(u.Duration.Value)));
                else until = "";
                P("LOCKED OUT since " + Fmt.Dt(u.LockoutTime) + " (" + Fmt.Ago(u.LockoutTime ?? DateTime.Now) + ")" + (until.Length > 0 ? " — " + until : ""), Theme.Red, true);
            }
            else
            {
                P("Not currently locked out" + (u.LockoutTime.HasValue ? " (last lockoutTime: " + Fmt.Dt(u.LockoutTime) + ", now expired)" : "") + ".", Theme.Green, true);
            }

            var withCount = r.Dcs.Where(d => d.BadPwdCount.HasValue).ToList();
            var maxBad = withCount.OrderByDescending(d => d.BadPwdCount).FirstOrDefault();
            var lastBad = r.Dcs.Where(d => d.BadPwdTime.HasValue).OrderByDescending(d => d.BadPwdTime).FirstOrDefault();
            KV("Enabled", u.Enabled ? "Yes" : "NO — account is disabled");
            KV("Password last set", Fmt.Dt(u.PwdLastSet) + (u.PwdLastSet.HasValue ? "  (" + Fmt.Ago(u.PwdLastSet.Value) + ")" : ""));
            if (maxBad != null) KV("Bad password count", maxBad.BadPwdCount + " (highest, on " + Source.Short(maxBad.Dc.Name) + ")");
            if (lastBad != null) KV("Last bad password", Fmt.Dt(lastBad.BadPwdTime) + " on " + Source.Short(lastBad.Dc.Name));
            var lastLogon = r.Dcs.Where(d => d.LastLogon.HasValue).OrderByDescending(d => d.LastLogon).FirstOrDefault();
            if (lastLogon != null) KV("Last successful logon", Fmt.Dt(lastLogon.LastLogon) + " on " + Source.Short(lastLogon.Dc.Name));
            if (u.AccountExpires.HasValue) KV("Account expires", Fmt.Dt(u.AccountExpires));
            KV("Lockout policy", u.Threshold.HasValue
                ? (u.Threshold.Value == 0 ? "lockout disabled (threshold 0)" :
                   u.Threshold + " bad attempts within " + Fmt.Interval(u.Window) + " → locked for " +
                   (u.Duration.HasValue && (u.Duration.Value == 0 || u.Duration.Value == long.MinValue) ? "until admin unlocks" : Fmt.Interval(u.Duration)))
                  + "   [" + u.PolicySource + "]"
                : "?   [" + u.PolicySource + "]");
            if (u.PolicyNote != null) P("   " + u.PolicyNote, Theme.Amber);
            if (u.PwdLastSet.HasValue && lastBad != null && lastBad.BadPwdTime > u.PwdLastSet && u.PwdLastSet.Value > DateTime.Now.AddDays(-14))
                P("   Password was changed recently and bad attempts came after it — classic stale-saved-password pattern.", Theme.Amber);

            // Lockout events
            P("");
            H2("Lockout events (last " + r.Hours + " h)");
            var lockouts = r.Events.Where(e => e.Id == 4740).OrderByDescending(e => e.Time).ToList();
            var lockoutsDedup = lockouts.GroupBy(e => e.Time.ToString("yyyyMMddHHmmss") + "|" + e.Host).Select(g => g.First()).ToList();
            if (lockoutsDedup.Count == 0)
                P(locked ? "  No 4740 found in the window — the lockout may be older than the window, or the PDC's log has rolled over / wasn't readable."
                         : "  None in this window.", Theme.Muted);
            foreach (var e in lockoutsDedup.Take(15))
                P("  " + Fmt.Dt(e.Time) + "   caller computer: " + (e.Host.Length > 0 ? e.Host : "(blank)") + "   [logged on " + e.Dc + "]",
                  Theme.Red);
            if (lockoutsDedup.Count > 15) P("  ... and " + (lockoutsDedup.Count - 15) + " more (see Events tab)", Theme.Muted);
            foreach (var e in r.Events.Where(e => e.Id == 4767).OrderByDescending(e => e.Time).Take(5))
                P("  " + Fmt.Dt(e.Time) + "   unlocked — " + e.Extra, Theme.Green);

            // Failure breakdown
            var fails = r.Events.Where(e => e.Id != 4740 && e.Id != 4767).ToList();
            P("");
            H2("Failed authentications: " + fails.Count);
            foreach (var g in fails.GroupBy(e => e.Kind + " — " + e.Meaning).OrderByDescending(g => g.Count()))
                P("  " + g.Count().ToString().PadLeft(5) + "   " + g.Key);

            // Top sources
            P("");
            H2("Most likely source(s)");
            var top = r.Sources.Take(3).ToList();
            if (top.Count == 0)
                P("  No failed-auth events found for this user in the window. If the account is locked, widen the window or check the warnings below.", Theme.Muted);
            foreach (var s in top)
            {
                P("  " + s.Label, Theme.Text, true);
                P("      " + s.Failures + " failure(s), " + s.Lockouts + " lockout(s)   first " + Fmt.Dt(s.First) + "   last " + Fmt.Dt(s.Last) +
                  "   via " + string.Join(", ", s.Dcs.OrderBy(x => x)));
                if (s.Reasons.Count > 0) P("      Reasons: " + string.Join("; ", s.Reasons));
                if (s.LogonTypes.Count > 0) P("      Logon types: " + string.Join(", ", s.LogonTypes));
                if (s.Hint.Length > 0) P("      → " + s.Hint, Theme.Blue);
            }
            if (r.Sources.Count > 3) P("  (" + r.Sources.Count + " sources in total — see the Likely sources tab)", Theme.Muted);

            // Warnings
            if (r.Warnings.Count > 0)
            {
                P("");
                H2("Coverage warnings");
                foreach (var w in r.Warnings) P("  ⚠ " + w, Theme.Amber);
            }
            P("");
            P("Domain " + r.Domain + " · PDC emulator " + r.Pdc + " · run " + Fmt.Dt(r.Started) + " on " + Environment.MachineName + " as " + Environment.UserDomainName + "\\" + Environment.UserName, Theme.Muted);
            rtbSummary.SelectionStart = 0;
            rtbSummary.ScrollToCaret();
        }

        static bool IsLocked(UserInfo u)
        {
            if (u.LockedComputed.HasValue) return u.LockedComputed.Value;
            if (!u.LockoutTime.HasValue) return false;
            if (!u.Duration.HasValue || u.Duration.Value == 0 || u.Duration.Value == long.MinValue) return true;
            return u.LockoutTime.Value.AddTicks(Math.Abs(u.Duration.Value)) > DateTime.Now;
        }

        void H(string text) { Append(text + "\n", new Font("Segoe UI Semibold", 14F), Theme.Text); }
        void H2(string text) { Append(text + "\n", new Font("Segoe UI Semibold", 11F), Theme.Text); }
        void P(string text) { P(text, Theme.Text, false); }
        void P(string text, Color c) { P(text, c, false); }
        void P(string text, Color c, bool bold) { Append(text + "\n", bold ? new Font(rtbSummary.Font, FontStyle.Bold) : rtbSummary.Font, c); }
        void KV(string k, string v)
        {
            Append("  " + k + ": ", new Font(rtbSummary.Font, FontStyle.Bold), Theme.Muted);
            Append(v + "\n", rtbSummary.Font, Theme.Text);
        }

        void Append(string text, Font f, Color c)
        {
            rtbSummary.SelectionStart = rtbSummary.TextLength;
            rtbSummary.SelectionLength = 0;
            rtbSummary.SelectionFont = f;
            rtbSummary.SelectionColor = c;
            rtbSummary.AppendText(text);
        }

        // ------------------------------------------------------------- grids

        void FillSources(ScanResult r)
        {
            srcTable = new DataTable();
            srcTable.Columns.Add("Machine name(s)");
            srcTable.Columns.Add("Source IP");
            srcTable.Columns.Add("DNS name");
            srcTable.Columns.Add("Lockouts", typeof(int));
            srcTable.Columns.Add("Failures", typeof(int));
            srcTable.Columns.Add("First seen", typeof(DateTime));
            srcTable.Columns.Add("Last seen", typeof(DateTime));
            srcTable.Columns.Add("Event types");
            srcTable.Columns.Add("Logon types");
            srcTable.Columns.Add("Reasons");
            srcTable.Columns.Add("DCs");
            srcTable.Columns.Add("Hint");
            srcTable.Columns.Add("_idx", typeof(int));
            for (int i = 0; i < r.Sources.Count; i++)
            {
                var s = r.Sources[i];
                srcTable.Rows.Add(s.Hosts.Count == 0 && s.Ip.Length == 0 ? "(none recorded)" : s.HostText, s.Ip, s.Resolved, s.Lockouts, s.Failures, s.First, s.Last,
                    string.Join(", ", s.Kinds), string.Join(", ", s.LogonTypes), string.Join("; ", s.Reasons),
                    string.Join(", ", s.Dcs.OrderBy(x => x)), s.Hint, i);
            }
            Bind(gridSources, srcTable, new Dictionary<string, int> { { "Machine name(s)", 160 }, { "Source IP", 120 }, { "DNS name", 180 }, { "Lockouts", 65 }, { "Failures", 65 }, { "Event types", 200 }, { "Logon types", 140 }, { "Reasons", 180 }, { "DCs", 120 }, { "Hint", 600 } });
            txtSourceDetail.Text = r.Sources.Count == 0 ? "" : "Select a source to see its events. Double-click to filter the Events tab to it.";
        }

        void FillEvents(ScanResult r)
        {
            evTable = new DataTable();
            evTable.Columns.Add("Time", typeof(DateTime));
            evTable.Columns.Add("DC");
            evTable.Columns.Add("ID", typeof(int));
            evTable.Columns.Add("Event");
            evTable.Columns.Add("Source machine");
            evTable.Columns.Add("Source IP");
            evTable.Columns.Add("Port");
            evTable.Columns.Add("Logon type");
            evTable.Columns.Add("Reason");
            evTable.Columns.Add("Status");
            evTable.Columns.Add("Process");
            evTable.Columns.Add("Auth");
            evTable.Columns.Add("Other");
            evTable.Columns.Add("User as sent");
            evTable.Columns.Add("_idx", typeof(int));
            for (int i = 0; i < r.Events.Count; i++)
            {
                var e = r.Events[i];
                evTable.Rows.Add(e.Time, e.Dc, e.Id, e.Kind, e.Host, e.Ip, e.Port, e.LogonType, e.Meaning, e.Status, e.Process, e.AuthPkg, e.Extra, e.User, i);
            }
            Bind(gridEvents, evTable, new Dictionary<string, int> { { "DC", 90 }, { "ID", 45 }, { "Event", 150 }, { "Source machine", 140 }, { "Source IP", 110 }, { "Port", 50 }, { "Logon type", 120 }, { "Reason", 200 }, { "Status", 120 }, { "Process", 200 }, { "Auth", 90 }, { "Other", 180 } });
            txtDetail.Text = "";
        }

        void FillDcs(ScanResult r)
        {
            dcTable = new DataTable();
            dcTable.Columns.Add("DC");
            dcTable.Columns.Add("PDC");
            dcTable.Columns.Add("Site");
            dcTable.Columns.Add("IP");
            dcTable.Columns.Add("badPwdCount");
            dcTable.Columns.Add("Last bad password");
            dcTable.Columns.Add("Last logon");
            dcTable.Columns.Add("lockoutTime");
            dcTable.Columns.Add("Events", typeof(int));
            dcTable.Columns.Add("Log starts");
            dcTable.Columns.Add("Secs", typeof(double));
            dcTable.Columns.Add("Problems");
            foreach (var d in r.Dcs)
            {
                var probs = new List<string>();
                if (d.LdapError != null) probs.Add("LDAP: " + d.LdapError);
                if (d.EventError != null) probs.Add("Event log: " + d.EventError);
                if (d.Truncated) probs.Add("Truncated at " + Engine.MaxEventsPerDc + " events");
                if (d.LogOldest.HasValue && d.LogOldest.Value > r.Started.AddHours(-r.Hours)) probs.Add("Log doesn't cover the whole window");
                dcTable.Rows.Add(d.Dc.Name, d.Dc.IsPdc ? "PDC" : "", d.Dc.Site, d.Dc.Ip,
                    d.BadPwdCount.HasValue ? d.BadPwdCount.ToString() : "-", Fmt.Dt(d.BadPwdTime), Fmt.Dt(d.LastLogon), Fmt.Dt(d.LockoutTime),
                    d.EventCount, Fmt.Dt(d.LogOldest), Math.Round(d.Seconds, 1), string.Join(" | ", probs));
            }
            Bind(gridDcs, dcTable, new Dictionary<string, int> { { "DC", 200 }, { "PDC", 40 }, { "Problems", 600 } });
        }

        static void Bind(DataGridView g, DataTable t, Dictionary<string, int> widths)
        {
            g.DataSource = null;
            g.DataSource = t;
            foreach (DataGridViewColumn c in g.Columns)
            {
                if (c.Name.StartsWith("_")) { c.Visible = false; continue; }
                if (c.ValueType == typeof(DateTime)) { c.DefaultCellStyle.Format = "yyyy-MM-dd HH:mm:ss"; c.Width = 135; }
                else c.AutoSizeMode = DataGridViewAutoSizeColumnMode.DisplayedCells;
                int w;
                if (widths.TryGetValue(c.Name, out w)) { c.AutoSizeMode = DataGridViewAutoSizeColumnMode.NotSet; c.Width = w; }
            }
        }

        void GridEvents_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            var row = gridEvents.Rows[e.RowIndex];
            var drv = row.DataBoundItem as DataRowView;
            if (drv == null) return;
            int id = (int)drv["ID"];
            if (id == 4740) { e.CellStyle.BackColor = Theme.LockRow; e.CellStyle.ForeColor = Theme.Text; }
            else if (id == 4767) { e.CellStyle.BackColor = Theme.UnlockRow; e.CellStyle.ForeColor = Theme.Text; }
        }

        void GridDcs_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            var drv = gridDcs.Rows[e.RowIndex].DataBoundItem as DataRowView;
            if (drv != null && ((string)drv["Problems"]).Length > 0) { e.CellStyle.BackColor = Theme.WarnRow; e.CellStyle.ForeColor = Theme.Text; }
        }

        void GridSources_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            var drv = gridSources.Rows[e.RowIndex].DataBoundItem as DataRowView;
            if (drv != null && (int)drv["Lockouts"] > 0) { e.CellStyle.BackColor = Theme.LockRow; e.CellStyle.ForeColor = Theme.Text; }
        }

        void ShowEventDetail()
        {
            if (last == null || gridEvents.CurrentRow == null) return;
            var drv = gridEvents.CurrentRow.DataBoundItem as DataRowView;
            if (drv == null) return;
            var e = last.Events[(int)drv["_idx"]];
            var sb = new StringBuilder();
            sb.AppendLine(e.Kind + "   (event " + e.Id + " on " + e.Dc + " at " + Fmt.Dt(e.Time) + ")");
            sb.AppendLine(new string('-', 70));
            if (e.Meaning.Length > 0) sb.AppendLine("Reason:   " + e.Meaning);
            foreach (var kv in e.Data) sb.AppendLine(kv.Key.PadRight(28) + kv.Value);
            sb.AppendLine();
            sb.AppendLine(Codes.Explain(e.Id));
            txtDetail.Text = sb.ToString().Replace("\n", "\r\n").Replace("\r\r", "\r");
        }

        void ShowSourceDetail()
        {
            if (last == null || gridSources.CurrentRow == null) return;
            var drv = gridSources.CurrentRow.DataBoundItem as DataRowView;
            if (drv == null) return;
            var s = last.Sources[(int)drv["_idx"]];
            var sb = new StringBuilder();
            sb.AppendLine(s.Label);
            sb.AppendLine(new string('-', 70));
            sb.AppendLine(s.Hint);
            sb.AppendLine();
            foreach (var e in s.Events.OrderByDescending(x => x.Time).Take(500))
                sb.AppendLine(Fmt.Dt(e.Time) + "  " + e.Dc.PadRight(14) + e.Id + "  " + e.Kind.PadRight(26) + (e.LogonType.Length > 0 ? ("type " + e.LogonType).PadRight(22) : "") + e.Meaning + (e.Process.Length > 0 ? "  [" + e.Process + "]" : ""));
            if (s.Events.Count > 500) sb.AppendLine("... " + (s.Events.Count - 500) + " more");
            txtSourceDetail.Text = sb.ToString().Replace("\n", "\r\n").Replace("\r\r", "\r");
        }

        void JumpToSourceEvents()
        {
            if (last == null || gridSources.CurrentRow == null || evTable == null) return;
            var drv = gridSources.CurrentRow.DataBoundItem as DataRowView;
            if (drv == null) return;
            var s = last.Sources[(int)drv["_idx"]];
            var idx = new HashSet<int>(s.Events.Select(e => last.Events.IndexOf(e)));
            evTable.DefaultView.RowFilter = "_idx IN (" + string.Join(",", idx) + ")";
            tabEvents.Text = "Events (" + idx.Count + " of " + last.Events.Count + " — filtered, right-click to clear)";
            if (gridEvents.ContextMenuStrip == null)
            {
                var cm = new ContextMenuStrip { Renderer = new DarkRenderer(), BackColor = Theme.Raised, ForeColor = Theme.Text };
                cm.Items.Add("Show all events", null, (a, b) => { evTable.DefaultView.RowFilter = ""; tabEvents.Text = "Events (" + last.Events.Count + ")"; });
                gridEvents.ContextMenuStrip = cm;
            }
            tabs.Select(tabEvents);
        }

        // ------------------------------------------------------------ actions

        void Unlock()
        {
            if (last == null) return;
            var u = last.User;
            if (MessageBox.Show(this, "Unlock " + u.Sam + " on " + last.Pdc + "?\n\nIf the source of the bad passwords isn't fixed, the account will lock again.",
                "Unlock account", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            try
            {
                using (var de = new DirectoryEntry("LDAP://" + last.Pdc + "/" + u.Dn.Replace("/", "\\/")))
                {
                    de.Properties["lockoutTime"].Value = 0;
                    de.CommitChanges();
                }
                MessageBox.Show(this, u.Sam + " unlocked on " + last.Pdc + ".", "Unlock account", MessageBoxButtons.OK, MessageBoxIcon.Information);
                StartTrace();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Unlock failed: " + ex.Message, "Unlock account", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        void Export()
        {
            if (last == null) return;
            using (var dlg = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = "lockout-" + last.User.Sam + "-" + last.Started.ToString("yyyyMMdd-HHmm") + ".csv" })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                string basePath = Path.Combine(Path.GetDirectoryName(dlg.FileName), Path.GetFileNameWithoutExtension(dlg.FileName));
                try
                {
                    WriteCsv(evTable, basePath + "-events.csv");
                    WriteCsv(srcTable, basePath + "-sources.csv");
                    WriteCsv(dcTable, basePath + "-dcs.csv");
                    File.WriteAllText(basePath + "-summary.txt", rtbSummary.Text.Replace("\n", "\r\n"), Encoding.UTF8);
                    MessageBox.Show(this, "Saved:\n" + basePath + "-events.csv\n" + basePath + "-sources.csv\n" + basePath + "-dcs.csv\n" + basePath + "-summary.txt",
                        "Export", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Export failed: " + ex.Message, "Export", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        static void WriteCsv(DataTable t, string path)
        {
            var cols = t.Columns.Cast<DataColumn>().Where(c => !c.ColumnName.StartsWith("_")).ToList();
            var sb = new StringBuilder();
            sb.AppendLine(string.Join(",", cols.Select(c => Csv(c.ColumnName))));
            foreach (DataRow row in t.Rows)
                sb.AppendLine(string.Join(",", cols.Select(c =>
                    Csv(row[c] is DateTime ? ((DateTime)row[c]).ToString("yyyy-MM-dd HH:mm:ss") : Convert.ToString(row[c])))));
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
        }

        static string Csv(string s)
        {
            if (s == null) return "";
            return s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
        }
    }
}
