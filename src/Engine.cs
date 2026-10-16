using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
using System.Security;
using System.Threading.Tasks;
using System.Xml;

namespace LockoutTracer
{
    class DcInfo
    {
        public string Name;
        public string Site;
        public string Ip;
        public bool IsPdc;
    }

    class DcResult
    {
        public DcInfo Dc;
        public long? BadPwdCount;
        public DateTime? BadPwdTime;
        public DateTime? LastLogon;
        public DateTime? LockoutTime;
        public DateTime? LogOldest;
        public int EventCount;
        public bool Truncated;
        public string LdapError;
        public string EventError;
        public double Seconds;
    }

    class Evt
    {
        public DateTime Time;
        public string Dc = "";
        public int Id;
        public string Kind = "";
        public string User = "";
        public string Host = "";
        public string Ip = "";
        public string Port = "";
        public string LogonType = "";
        public string Status = "";
        public string Meaning = "";
        public string Process = "";
        public string AuthPkg = "";
        public string Extra = "";
        public Dictionary<string, string> Data = new Dictionary<string, string>();
        public string Xml = "";
    }

    class UserInfo
    {
        public string Sam, Upn, Dn, DisplayName, Description, Mail;
        public bool Enabled;
        public bool? LockedComputed;
        public DateTime? PwdLastSet, LockoutTime, LastLogonTimestamp, AccountExpires;
        public long? Threshold, Duration, Window;   // raw AD values (100ns intervals, negative)
        public string PolicySource = "Default Domain Policy";
        public string PolicyNote;
    }

    class Source
    {
        public string Ip = "";
        public HashSet<string> Hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public string Resolved = "";
        public int Failures, Lockouts;
        public DateTime First = DateTime.MaxValue, Last = DateTime.MinValue;
        public HashSet<string> Kinds = new HashSet<string>();
        public HashSet<string> LogonTypes = new HashSet<string>();
        public HashSet<string> Dcs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Processes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Reasons = new HashSet<string>();
        public List<Evt> Events = new List<Evt>();
        public string Hint = "";

        public string HostText { get { return Hosts.Count == 0 ? "" : string.Join(", ", Hosts.OrderBy(h => h)); } }
        public string Label
        {
            get
            {
                var parts = new List<string>();
                if (Hosts.Count > 0) parts.Add(HostText);
                if (Ip.Length > 0) parts.Add(Ip);
                if (Resolved.Length > 0 && !Hosts.Any(h => Short(Resolved).Equals(Short(h), StringComparison.OrdinalIgnoreCase)))
                    parts.Add("(" + Resolved + ")");
                return parts.Count == 0 ? "(no source recorded)" : string.Join("  ", parts);
            }
        }
        public static string Short(string host)
        {
            int i = host.IndexOf('.');
            return i > 0 ? host.Substring(0, i) : host;
        }
    }

    class ScanResult
    {
        public string Domain, Pdc, Input;
        public int Hours;
        public DateTime Started;
        public UserInfo User;
        public List<DcResult> Dcs = new List<DcResult>();
        public List<Evt> Events = new List<Evt>();
        public List<Source> Sources = new List<Source>();
        public List<string> Warnings = new List<string>();
    }

    static class Engine
    {
        public const int MaxEventsPerDc = 5000;
        const long AuditFailureKeyword = 4503599627370496; // 0x10000000000000

        public static ScanResult Run(string input, int hours, bool allDcs, bool resolveDns, Action<string> progress)
        {
            var res = new ScanResult { Input = input, Hours = hours, Started = DateTime.Now };

            progress("Locating domain and PDC emulator...");
            Domain dom;
            try { dom = Domain.GetCurrentDomain(); }
            catch (Exception ex)
            {
                throw new ApplicationException("Could not contact the domain: " + ex.Message +
                    "\n\nRun this on a domain controller (or a domain-joined machine) as a domain admin.");
            }
            res.Domain = dom.Name;
            res.Pdc = dom.PdcRoleOwner.Name;

            var dcs = new List<DcInfo>();
            foreach (DomainController dc in dom.DomainControllers)
            {
                var info = new DcInfo { Name = dc.Name };
                try { info.Site = dc.SiteName; } catch { info.Site = "?"; }
                try { info.Ip = dc.IPAddress; } catch { info.Ip = ""; }
                info.IsPdc = string.Equals(dc.Name, res.Pdc, StringComparison.OrdinalIgnoreCase);
                if (allDcs || info.IsPdc || IsLocal(info.Name)) dcs.Add(info);
            }
            if (!dcs.Any(d => d.IsPdc)) dcs.Insert(0, new DcInfo { Name = res.Pdc, IsPdc = true, Site = "?", Ip = "" });
            dcs = dcs.OrderByDescending(d => d.IsPdc).ThenBy(d => d.Name).ToList();

            progress("Looking up " + input + " on " + res.Pdc + "...");
            string nc;
            using (var rootDse = new DirectoryEntry("LDAP://" + res.Pdc + "/RootDSE"))
                nc = rootDse.Properties["defaultNamingContext"].Value.ToString();
            res.User = FindUser(res.Pdc, nc, input);
            ReadPolicy(res.Pdc, nc, res.User);

            var names = UserNameVariants(input, res.User);
            string query = BuildQuery(names, hours);

            var pending = new HashSet<string>(dcs.Select(d => d.Name), StringComparer.OrdinalIgnoreCase);
            Action report = () =>
            {
                string[] p; lock (pending) p = pending.ToArray();
                progress("Querying " + dcs.Count + " DC(s)... waiting on " + p.Length + ": " + string.Join(", ", p.Select(Source.Short)));
            };
            report();

            var results = new List<DcResult>();
            var events = new List<Evt>();
            Parallel.ForEach(dcs, new ParallelOptions { MaxDegreeOfParallelism = 8 }, dc =>
            {
                var r = new DcResult { Dc = dc };
                var sw = System.Diagnostics.Stopwatch.StartNew();
                QueryDcLdap(dc, res.User.Dn, r);
                List<Evt> evs = QueryDcEvents(dc, query, r);
                r.Seconds = sw.Elapsed.TotalSeconds;
                lock (results) { results.Add(r); events.AddRange(evs); }
                lock (pending) pending.Remove(dc.Name);
                report();
            });

            res.Dcs = results.OrderByDescending(r => r.Dc.IsPdc).ThenBy(r => r.Dc.Name).ToList();
            res.Events = events.OrderByDescending(e => e.Time).ToList();

            Dictionary<string, string> dns = new Dictionary<string, string>();
            if (resolveDns)
            {
                progress("Resolving source IPs...");
                dns = ResolveIps(res.Events.Select(e => e.Ip));
            }
            res.Sources = BuildSources(res.Events, dns);

            DateTime windowStart = res.Started.AddHours(-hours);
            foreach (var r in res.Dcs)
            {
                if (r.LdapError != null) res.Warnings.Add(r.Dc.Name + ": LDAP query failed - " + r.LdapError);
                if (r.EventError != null) res.Warnings.Add(r.Dc.Name + ": Security log NOT read - " + r.EventError);
                if (r.Truncated) res.Warnings.Add(r.Dc.Name + ": more than " + MaxEventsPerDc + " matching events; only the newest were loaded.");
                if (r.LogOldest.HasValue && r.LogOldest.Value > windowStart)
                    res.Warnings.Add(r.Dc.Name + ": Security log only goes back to " + Fmt.Dt(r.LogOldest) +
                                     " - older events in your window have been overwritten.");
            }
            progress("Done.");
            return res;
        }

        public static bool IsLocal(string dcName)
        {
            return string.Equals(Source.Short(dcName), Environment.MachineName, StringComparison.OrdinalIgnoreCase);
        }

        // ---------------------------------------------------------------- LDAP

        static string LdapEscape(string s)
        {
            return s.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");
        }

        static string AdsPath(string server, string dn)
        {
            return "LDAP://" + server + "/" + dn.Replace("/", "\\/");
        }

        static SearchResult BaseSearch(string server, string dn, params string[] props)
        {
            using (var de = new DirectoryEntry(AdsPath(server, dn)))
            using (var ds = new DirectorySearcher(de, "(objectClass=*)", props, SearchScope.Base))
            {
                ds.ClientTimeout = TimeSpan.FromSeconds(20);
                return ds.FindOne();
            }
        }

        static long? GetLong(SearchResult r, string prop)
        {
            if (r == null || !r.Properties.Contains(prop) || r.Properties[prop].Count == 0) return null;
            try { return Convert.ToInt64(r.Properties[prop][0]); } catch { return null; }
        }

        static string GetStr(SearchResult r, string prop)
        {
            if (r == null || !r.Properties.Contains(prop) || r.Properties[prop].Count == 0) return null;
            return Convert.ToString(r.Properties[prop][0]);
        }

        static UserInfo FindUser(string pdc, string nc, string input)
        {
            string name = input.Trim();
            int slash = name.IndexOf('\\');
            if (slash >= 0) name = name.Substring(slash + 1);
            string sam = name.Contains("@") ? name.Substring(0, name.IndexOf('@')) : name;
            string esc = LdapEscape(name), escSam = LdapEscape(sam);

            using (var de = new DirectoryEntry("LDAP://" + pdc + "/" + nc))
            using (var ds = new DirectorySearcher(de))
            {
                ds.Filter = "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=" + escSam + ")(userPrincipalName=" + esc + ")))";
                ds.PropertiesToLoad.AddRange(new[] { "sAMAccountName", "userPrincipalName", "distinguishedName", "displayName",
                    "userAccountControl", "pwdLastSet", "lockoutTime", "lastLogonTimestamp", "mail", "description", "accountExpires" });
                ds.SizeLimit = 5;
                ds.ClientTimeout = TimeSpan.FromSeconds(30);
                var found = ds.FindAll().Cast<SearchResult>().ToList();
                if (found.Count == 0) throw new ApplicationException("No user account matching '" + input + "' was found in " + nc + ".");
                SearchResult r = found.FirstOrDefault(x => string.Equals(GetStr(x, "sAMAccountName"), sam, StringComparison.OrdinalIgnoreCase)) ?? found[0];

                var u = new UserInfo
                {
                    Sam = GetStr(r, "sAMAccountName"),
                    Upn = GetStr(r, "userPrincipalName") ?? "",
                    Dn = GetStr(r, "distinguishedName"),
                    DisplayName = GetStr(r, "displayName") ?? "",
                    Description = GetStr(r, "description") ?? "",
                    Mail = GetStr(r, "mail") ?? "",
                    Enabled = ((GetLong(r, "userAccountControl") ?? 0) & 2) == 0,
                    PwdLastSet = Fmt.FromFileTime(GetLong(r, "pwdLastSet")),
                    LockoutTime = Fmt.FromFileTime(GetLong(r, "lockoutTime")),
                    LastLogonTimestamp = Fmt.FromFileTime(GetLong(r, "lastLogonTimestamp")),
                    AccountExpires = Fmt.FromFileTime(GetLong(r, "accountExpires")),
                };
                try
                {
                    var c = BaseSearch(pdc, u.Dn, "msDS-User-Account-Control-Computed", "msDS-ResultantPSO");
                    long? computed = GetLong(c, "msDS-User-Account-Control-Computed");
                    if (computed.HasValue) u.LockedComputed = (computed.Value & 0x10) != 0;
                    string pso = GetStr(c, "msDS-ResultantPSO");
                    if (!string.IsNullOrEmpty(pso)) u.PolicySource = pso;
                }
                catch { }
                return u;
            }
        }

        static void ReadPolicy(string pdc, string nc, UserInfo u)
        {
            try
            {
                if (u.PolicySource.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                {
                    var p = BaseSearch(pdc, u.PolicySource, "msDS-LockoutThreshold", "msDS-LockoutDuration", "msDS-LockoutObservationWindow");
                    u.Threshold = GetLong(p, "msDS-LockoutThreshold");
                    u.Duration = GetLong(p, "msDS-LockoutDuration");
                    u.Window = GetLong(p, "msDS-LockoutObservationWindow");
                    if (!u.Threshold.HasValue) u.PolicyNote = "Fine-grained password policy applies but its settings could not be read (permissions?).";
                    string cn = u.PolicySource.Substring(3);
                    int comma = cn.IndexOf(',');
                    u.PolicySource = "Fine-grained PSO '" + (comma > 0 ? cn.Substring(0, comma) : cn) + "'";
                }
                else
                {
                    var p = BaseSearch(pdc, nc, "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow");
                    u.Threshold = GetLong(p, "lockoutThreshold");
                    u.Duration = GetLong(p, "lockoutDuration");
                    u.Window = GetLong(p, "lockOutObservationWindow");
                }
            }
            catch (Exception ex) { u.PolicyNote = "Could not read lockout policy: " + ex.Message; }
        }

        static void QueryDcLdap(DcInfo dc, string dn, DcResult r)
        {
            try
            {
                var s = BaseSearch(dc.Name, dn, "badPwdCount", "badPasswordTime", "lastLogon", "lockoutTime");
                r.BadPwdCount = GetLong(s, "badPwdCount") ?? 0;
                r.BadPwdTime = Fmt.FromFileTime(GetLong(s, "badPasswordTime"));
                r.LastLogon = Fmt.FromFileTime(GetLong(s, "lastLogon"));
                r.LockoutTime = Fmt.FromFileTime(GetLong(s, "lockoutTime"));
            }
            catch (Exception ex) { r.LdapError = ex.Message.Trim(); }
        }

        // ---------------------------------------------------------- Event logs

        static List<string> UserNameVariants(string input, UserInfo u)
        {
            // Event-log XPath string compares are exact, and clients send the name in whatever case was typed.
            var set = new HashSet<string>(StringComparer.Ordinal);
            string typed = input.Trim();
            int slash = typed.IndexOf('\\');
            if (slash >= 0) typed = typed.Substring(slash + 1);
            foreach (string n in new[] { typed, u.Sam, u.Upn })
            {
                if (string.IsNullOrEmpty(n)) continue;
                set.Add(n); set.Add(n.ToLowerInvariant()); set.Add(n.ToUpperInvariant());
                if (n.Length > 1) set.Add(char.ToUpperInvariant(n[0]) + n.Substring(1).ToLowerInvariant());
            }
            return set.ToList();
        }

        public static string BuildQuery(IEnumerable<string> names, int hours)
        {
            long ms = (long)hours * 3600000L;
            string nameClause = string.Join(" or ", names.Select(n => "Data[@Name='TargetUserName']=\"" + SecurityElement.Escape(n) + "\""));
            string ids = "EventID=4740 or EventID=4767 or EventID=4625 or EventID=4771 or " +
                         "((EventID=4768 or EventID=4776) and band(Keywords," + AuditFailureKeyword + "))";
            string xpath = "*[System[(" + ids + ") and TimeCreated[timediff(@SystemTime) &lt;= " + ms + "]]] and *[EventData[" + nameClause + "]]";
            return "<QueryList><Query Id=\"0\" Path=\"Security\"><Select Path=\"Security\">" + xpath + "</Select></Query></QueryList>";
        }

        static EventLogSession Session(DcInfo dc)
        {
            return IsLocal(dc.Name) ? new EventLogSession() : new EventLogSession(dc.Name);
        }

        static List<Evt> QueryDcEvents(DcInfo dc, string query, DcResult r)
        {
            var list = new List<Evt>();
            try
            {
                using (var session = Session(dc))
                {
                    try
                    {
                        var oq = new EventLogQuery("Security", PathType.LogName, "*") { Session = session };
                        using (var reader = new EventLogReader(oq))
                        using (var first = reader.ReadEvent())
                            if (first != null) r.LogOldest = first.TimeCreated;
                    }
                    catch { }

                    var q = new EventLogQuery("Security", PathType.LogName, query) { Session = session, ReverseDirection = true };
                    using (var reader = new EventLogReader(q))
                    {
                        EventRecord rec;
                        while ((rec = reader.ReadEvent()) != null)
                        {
                            using (rec) list.Add(Parse(rec.ToXml(), rec.TimeCreated ?? DateTime.MinValue, dc.Name));
                            if (list.Count >= MaxEventsPerDc) { r.Truncated = true; break; }
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                r.EventError = IsLocal(dc.Name)
                    ? "access denied (run elevated / as Administrator)"
                    : "access denied (need Domain Admin or 'Event Log Readers' on that DC)";
            }
            catch (EventLogException ex)
            {
                r.EventError = ex.Message.Trim() + (IsLocal(dc.Name) ? "" : " (is the 'Remote Event Log Management' firewall rule enabled on that DC?)");
            }
            catch (Exception ex) { r.EventError = ex.Message.Trim(); }
            r.EventCount = list.Count;
            return list;
        }

        static string D(Dictionary<string, string> d, string key)
        {
            string v;
            if (!d.TryGetValue(key, out v) || v == null) return "";
            v = v.Trim();
            return v == "-" ? "" : v;
        }

        public static Evt Parse(string xml, DateTime time, string dc)
        {
            var e = new Evt { Time = time, Dc = Source.Short(dc), Xml = xml };
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            var ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event");
            var idNode = doc.SelectSingleNode("/e:Event/e:System/e:EventID", ns);
            e.Id = idNode != null ? int.Parse(idNode.InnerText) : 0;
            foreach (XmlNode n in doc.SelectNodes("/e:Event/e:EventData/e:Data", ns))
            {
                var a = n.Attributes["Name"];
                if (a != null) e.Data[a.Value] = n.InnerText;
            }
            var d = e.Data;
            e.User = D(d, "TargetUserName");
            switch (e.Id)
            {
                case 4740:
                    e.Kind = "LOCKOUT";
                    e.Host = CleanHost(D(d, "TargetDomainName"));   // 4740 puts the Caller Computer Name here
                    e.Meaning = "Account locked out. Caller computer = where the bad attempts came from" + (e.Host.Length == 0 ? " (blank: source not known to this DC)" : "");
                    break;
                case 4767:
                    e.Kind = "Unlocked";
                    e.Extra = "Unlocked by " + D(d, "SubjectDomainName") + "\\" + D(d, "SubjectUserName");
                    e.Meaning = "Account was unlocked";
                    break;
                case 4625:
                    e.Kind = "Logon failure";
                    e.Host = CleanHost(D(d, "WorkstationName"));
                    e.Ip = CleanIp(D(d, "IpAddress"));
                    e.Port = D(d, "IpPort") == "0" ? "" : D(d, "IpPort");
                    e.LogonType = Codes.LogonType(D(d, "LogonType"));
                    string st = D(d, "Status"), sub = D(d, "SubStatus");
                    bool useSub = sub.Length > 0 && sub != "0x0";
                    e.Status = useSub ? st + " / " + sub : st;
                    e.Meaning = Codes.NtStatus(useSub ? sub : st);
                    e.Process = D(d, "ProcessName");
                    e.AuthPkg = (D(d, "AuthenticationPackageName") + " " + D(d, "LogonProcessName")).Trim();
                    break;
                case 4771:
                    e.Kind = "Kerberos pre-auth failed";
                    e.Ip = CleanIp(D(d, "IpAddress"));
                    e.Port = D(d, "IpPort") == "0" ? "" : D(d, "IpPort");
                    e.Status = D(d, "Status");
                    e.Meaning = Codes.Kerberos(e.Status);
                    e.AuthPkg = "Kerberos";
                    e.Extra = "Service: " + D(d, "ServiceName");
                    break;
                case 4768:
                    e.Kind = "Kerberos TGT failed";
                    e.Ip = CleanIp(D(d, "IpAddress"));
                    e.Port = D(d, "IpPort") == "0" ? "" : D(d, "IpPort");
                    e.Status = D(d, "Status");
                    e.Meaning = Codes.Kerberos(e.Status);
                    e.AuthPkg = "Kerberos";
                    e.Extra = "Service: " + D(d, "ServiceName");
                    break;
                case 4776:
                    e.Kind = "NTLM auth failed";
                    e.Host = CleanHost(D(d, "Workstation"));
                    e.Status = D(d, "Status");
                    e.Meaning = Codes.NtStatus(e.Status);
                    e.AuthPkg = "NTLM";
                    e.Extra = "Validated by: " + D(d, "PackageName");
                    break;
                default:
                    e.Kind = "Event " + e.Id;
                    break;
            }
            return e;
        }

        static string CleanHost(string h)
        {
            h = h.Trim().TrimStart('\\');
            return h == "-" ? "" : h.ToUpperInvariant();
        }

        static string CleanIp(string ip)
        {
            ip = ip.Trim();
            if (ip == "-" || ip == "") return "";
            if (ip.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase)) ip = ip.Substring(7);
            return ip;
        }

        public static bool IsLoopback(string ip)
        {
            return ip == "127.0.0.1" || ip == "::1";
        }

        // ------------------------------------------------------------- Sources

        static Dictionary<string, string> ResolveIps(IEnumerable<string> ips)
        {
            var map = new Dictionary<string, string>();
            var distinct = ips.Where(i => i.Length > 0 && !IsLoopback(i)).Distinct().ToList();
            Parallel.ForEach(distinct, new ParallelOptions { MaxDegreeOfParallelism = 16 }, ip =>
            {
                string name = "";
                try
                {
                    var ar = Dns.BeginGetHostEntry(ip, null, null);
                    if (ar.AsyncWaitHandle.WaitOne(2500))
                    {
                        var he = Dns.EndGetHostEntry(ar);
                        if (he.HostName != ip) name = he.HostName.ToUpperInvariant();
                    }
                }
                catch { }
                lock (map) map[ip] = name;
            });
            return map;
        }

        public static List<Source> BuildSources(List<Evt> events, Dictionary<string, string> dns)
        {
            var byKey = new Dictionary<string, Source>(StringComparer.OrdinalIgnoreCase);
            var seenLockouts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in events)
            {
                if (e.Id == 4767) continue;
                // The PDC and the authenticating DC can both log the same 4740.
                if (e.Id == 4740 && !seenLockouts.Add(e.Host + "|" + e.Time.ToString("yyyyMMddHHmmss"))) continue;
                string key, ip = e.Ip;
                if (ip.Length > 0)
                {
                    if (IsLoopback(ip)) ip = ip + " (on " + e.Dc + ")";
                    key = "ip:" + ip;
                }
                else if (e.Host.Length > 0) key = "host:" + Source.Short(e.Host);
                else key = "none:" + e.Kind;

                Source s;
                if (!byKey.TryGetValue(key, out s))
                {
                    s = new Source { Ip = ip };
                    string r;
                    if (ip.Length > 0 && dns.TryGetValue(ip, out r)) s.Resolved = r;
                    byKey[key] = s;
                }
                Add(s, e);
            }

            // Fold name-only groups (4740 caller / 4776 workstation) into an IP group for the same machine.
            foreach (var kv in byKey.Where(k => k.Key.StartsWith("host:")).ToList())
            {
                string shortName = kv.Key.Substring(5);
                var target = byKey.Where(k => k.Key.StartsWith("ip:")).Select(k => k.Value).FirstOrDefault(s =>
                    (s.Resolved.Length > 0 && Source.Short(s.Resolved).Equals(shortName, StringComparison.OrdinalIgnoreCase)) ||
                    s.Hosts.Any(h => Source.Short(h).Equals(shortName, StringComparison.OrdinalIgnoreCase)));
                if (target == null) continue;
                foreach (var e in kv.Value.Events) Add(target, e);
                byKey.Remove(kv.Key);
            }

            var list = byKey.Values.ToList();
            foreach (var s in list) s.Hint = Hint(s);
            return list.OrderByDescending(s => s.Lockouts).ThenByDescending(s => s.Failures).ThenByDescending(s => s.Last).ToList();
        }

        static void Add(Source s, Evt e)
        {
            s.Events.Add(e);
            if (e.Host.Length > 0) s.Hosts.Add(e.Host);
            if (e.Id == 4740) s.Lockouts++; else s.Failures++;
            if (e.Time < s.First) s.First = e.Time;
            if (e.Time > s.Last) s.Last = e.Time;
            s.Kinds.Add(e.Kind);
            if (e.LogonType.Length > 0) s.LogonTypes.Add(e.LogonType);
            s.Dcs.Add(e.Dc);
            if (e.Process.Length > 0) s.Processes.Add(e.Process);
            if (e.Id != 4740 && e.Meaning.Length > 0) s.Reasons.Add(e.Meaning);
        }

        static string Hint(Source s)
        {
            var h = new List<string>();
            var ev = s.Events;
            if (s.Lockouts > 0) h.Add("DC recorded this machine as the lockout caller.");
            if (ev.Any(e => e.Status.ToLowerInvariant().Contains("0xc0000234") || e.Status.Equals("0x12", StringComparison.OrdinalIgnoreCase)))
                h.Add("Still retrying after lockout - something automated.");
            Func<string, bool> lt = t => ev.Any(e => e.LogonType.StartsWith(t + " "));
            if (lt("5")) h.Add("Type 5: a Windows SERVICE on this host runs as the user with an old password (services.msc).");
            if (lt("4")) h.Add("Type 4: a SCHEDULED TASK on this host runs as the user with an old password.");
            if (lt("8")) h.Add("Type 8 (cleartext): IIS/basic auth - OWA, ActiveSync, RD Gateway or a web app on this host. Check its IIS logs for the client IP.");
            if (lt("2") || lt("7") || lt("11")) h.Add("Interactive/unlock: someone typing the wrong password at this machine, or a stale locked session.");
            if (lt("10")) h.Add("RDP: wrong password, or a disconnected RDP session with old credentials.");
            if (lt("3")) h.Add("Network logon: mapped drive, saved credentials, or an app connecting with stored credentials.");
            if (ev.Any(e => e.Id == 4771 || e.Id == 4768))
                h.Add("Kerberos: a process/device with a cached OLD password (Credential Manager, mapped drives, Outlook, phone Wi-Fi/802.1X, VPN).");
            if (ev.Any(e => e.Id == 4776 && e.Host.Length == 0))
                h.Add("NTLM with no workstation name - usually a server relaying auth (Exchange, NPS/RADIUS, VPN, web app). Check that server's logs.");
            else if (ev.Any(e => e.Id == 4776))
                h.Add("NTLM: name is as reported by the client; check that machine's own Security log (4625) for the process.");
            if (s.Ip.Contains("(on "))
                h.Add("Loopback: the failing process is running ON the DC itself.");
            if (s.Processes.Count > 0) h.Add("Process: " + string.Join(", ", s.Processes));
            return string.Join(" ", h);
        }
    }

    static class Codes
    {
        public static string Explain(int id)
        {
            switch (id)
            {
                case 4740: return "4740: logged by the PDC emulator (and the DC that saw the final bad password) when the account locks.\r\nCaller Computer Name (TargetDomainName field) is the machine the DC thinks sent the bad password.\r\nIf it's an Exchange/RD Gateway/NPS/web server, the real client is behind it - check that server's logs.";
                case 4767: return "4767: the account was unlocked (Subject = who did it).";
                case 4625: return "4625: a logon failed AT the DC itself (e.g. someone mapping a DC share, RDP to the DC, or a process on the DC).\r\nIpAddress/WorkstationName show the client; LogonType shows how (3 network, 5 service, 4 task, 8 cleartext/IIS, 10 RDP).";
                case 4771: return "4771: Kerberos pre-authentication failed - the client at IpAddress tried to get a ticket with a wrong password (0x18).\r\n0x12 means the account was already locked/disabled when the client tried.\r\nTo find the process, look at 4625 / Kerberos logs on the client machine at IpAddress.";
                case 4768: return "4768 (failure): a Kerberos TGT request was refused - status explains why.";
                case 4776: return "4776: NTLM credential validation failed. Workstation is the name the client sent (can be blank or spoofed).\r\nIf blank, the auth was relayed by a server (Exchange, NPS, VPN, IIS). Enable NTLM auditing (Netlogon debug logging) for more detail.";
                default: return "";
            }
        }

        public static string LogonType(string t)
        {
            switch (t)
            {
                case "2": return "2 Interactive";
                case "3": return "3 Network";
                case "4": return "4 Batch (sched. task)";
                case "5": return "5 Service";
                case "7": return "7 Unlock";
                case "8": return "8 NetworkCleartext";
                case "9": return "9 NewCredentials (runas)";
                case "10": return "10 RemoteInteractive (RDP)";
                case "11": return "11 CachedInteractive";
                default: return t;
            }
        }

        public static string NtStatus(string code)
        {
            switch (code.Trim().ToLowerInvariant())
            {
                case "0x0": return "Success";
                case "0xc000006a": return "Bad password";
                case "0xc0000064": return "User name does not exist";
                case "0xc000006d": return "Bad user name or password";
                case "0xc000006e": return "Account restriction";
                case "0xc000006f": return "Logon outside allowed hours";
                case "0xc0000070": return "Not allowed to log on from this workstation";
                case "0xc0000071": return "Password expired";
                case "0xc0000072": return "Account disabled";
                case "0xc0000193": return "Account expired";
                case "0xc0000224": return "Password must change at next logon";
                case "0xc0000234": return "Account locked out (attempt while already locked)";
                case "0xc000015b": return "Logon type not granted on that machine";
                case "0xc0000133": return "Clock out of sync with DC";
                case "0xc000018c": return "Trust relationship failed";
                case "0xc0000192": return "Netlogon service not started";
                case "0xc000005e": return "No logon servers available";
                case "0xc0000413": return "Blocked by authentication firewall";
                case "0xc0000371": return "Local account store lacks the secret";
                default: return code;
            }
        }

        public static string Kerberos(string code)
        {
            switch (code.Trim().ToLowerInvariant())
            {
                case "0x0": return "Success";
                case "0x6": return "Client not found (bad user name)";
                case "0x7": return "Server not found in Kerberos database";
                case "0xc": return "Policy restriction (workstation/logon hours)";
                case "0xe": return "Encryption type not supported";
                case "0x12": return "Account disabled, expired or LOCKED OUT";
                case "0x17": return "Password expired";
                case "0x18": return "Bad password";
                case "0x1f": return "Integrity check failed";
                case "0x20": return "Ticket expired";
                case "0x25": return "Clock skew too great";
                default: return code;
            }
        }
    }

    static class Fmt
    {
        public static string Dt(DateTime? d)
        {
            return d.HasValue ? d.Value.ToString("yyyy-MM-dd HH:mm:ss") : "-";
        }

        public static DateTime? FromFileTime(long? v)
        {
            if (!v.HasValue || v.Value <= 0 || v.Value == long.MaxValue) return null;
            try { return DateTime.FromFileTime(v.Value); } catch { return null; }
        }

        public static string Interval(long? raw)
        {
            if (!raw.HasValue) return "?";
            if (raw.Value == long.MinValue) return "forever";
            var t = TimeSpan.FromTicks(Math.Abs(raw.Value));
            if (t.TotalMinutes < 1) return (int)t.TotalSeconds + " s";
            if (t.TotalHours < 2) return (int)t.TotalMinutes + " min";
            return t.TotalHours.ToString("0.#") + " h";
        }

        public static string Ago(DateTime d)
        {
            var t = DateTime.Now - d;
            if (t.TotalMinutes < 1) return "just now";
            if (t.TotalHours < 1) return (int)t.TotalMinutes + " min ago";
            if (t.TotalDays < 2) return t.TotalHours.ToString("0.#") + " h ago";
            return (int)t.TotalDays + " days ago";
        }
    }
}
