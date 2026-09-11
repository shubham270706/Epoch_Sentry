##! Epoch Sentry — Zeek capture entry point.
##!
##! Run Zeek with THIS script instead of the stock `local` policy:
##!
##!     zeek -i <interface> local_capture.zeek
##!
##! Rationale for what's in here:
##!
##!   1. conn.log is the ONLY thing zeek_daemon.py reads. Zeek's default
##!      startup (and doubly so the `local` policy bundle) writes a dozen+
##!      other logs — dns.log, http.log, ssl.log, x509.log, files.log,
##!      weird.log, notice.log, software.log, known_*.log, ... — none of
##!      which this pipeline ingests. On a box meant to capture *endlessly*
##!      until someone hits Stop, that's pure disk churn for zero benefit,
##!      so every stream except Conn::LOG is switched off below.
##!
##!   2. We still need the DNS *analyzer* running (not its log) because
##!      enrich_dns.zeek hooks the dns_request event to compute
##!      dns_query_entropy and writes it straight onto Conn::Info. Disabling
##!      DNS::LOG does not disable the DNS analyzer/event — only the log
##!      writer — so this keeps working.
##!
##!   3. conn.log itself is rotated frequently (see redef below) and each
##!      rotated file is deleted the instant Zeek finishes writing it.
##!      This is safe: zeek_daemon.py tails conn.log by open file
##!      descriptor, and on Linux an open fd keeps reading a file's data
##!      just fine even after the file is unlinked — the data isn't
##!      reclaimed until the daemon's fd is closed (which happens right
##!      after it drains the last line and reopens the fresh file Zeek
##!      creates at the same path). Net effect: at most one rotation
##!      interval's worth of conn.log ever sits on disk, and the durable
##!      copy of everything lives in SQLite (which has its own retention
##!      trimming — see zeek_daemon.py).

@load ./enrich_dns.zeek

module EpochSentry;

# Rotate conn.log often so the on-disk footprint of the "live" file stays
# small even under sustained, high-volume, endless capture.
redef Log::default_rotation_interval = 10 min;

# Delete a log file the moment Zeek finishes rotating it out. See note (3)
# above for why this doesn't race with zeek_daemon.py's tailing.
function epoch_sentry_delete_rotated(info: Log::RotationInfo): bool
    {
    system(fmt("rm -f -- %s", info$fname));
    return T;
    }

redef Log::default_rotation_postprocessors += {
    [Log::WRITER_ASCII] = epoch_sentry_delete_rotated
};

event zeek_init() &priority=-5
    {
    # Keep: Conn::LOG (essential — the whole pipeline is built on it).
    # Everything else, only if the identifier exists in this Zeek build/
    # policy mix (@ifdef guards this file against version differences).
    @ifdef ( DNS::LOG )
        Log::disable_stream(DNS::LOG);
    @endif
    @ifdef ( HTTP::LOG )
        Log::disable_stream(HTTP::LOG);
    @endif
    @ifdef ( SSL::LOG )
        Log::disable_stream(SSL::LOG);
    @endif
    @ifdef ( X509::LOG )
        Log::disable_stream(X509::LOG);
    @endif
    @ifdef ( Files::LOG )
        Log::disable_stream(Files::LOG);
    @endif
    @ifdef ( Weird::LOG )
        Log::disable_stream(Weird::LOG);
    @endif
    @ifdef ( Notice::LOG )
        Log::disable_stream(Notice::LOG);
    @endif
    @ifdef ( DPD::LOG )
        Log::disable_stream(DPD::LOG);
    @endif
    @ifdef ( PacketFilter::LOG )
        Log::disable_stream(PacketFilter::LOG);
    @endif
    @ifdef ( LoadedScripts::LOG )
        Log::disable_stream(LoadedScripts::LOG);
    @endif
    @ifdef ( Software::LOG )
        Log::disable_stream(Software::LOG);
    @endif
    @ifdef ( SSH::LOG )
        Log::disable_stream(SSH::LOG);
    @endif
    @ifdef ( FTP::LOG )
        Log::disable_stream(FTP::LOG);
    @endif
    @ifdef ( SMTP::LOG )
        Log::disable_stream(SMTP::LOG);
    @endif
    @ifdef ( Tunnel::LOG )
        Log::disable_stream(Tunnel::LOG);
    @endif
    @ifdef ( SNMP::LOG )
        Log::disable_stream(SNMP::LOG);
    @endif
    @ifdef ( RDP::LOG )
        Log::disable_stream(RDP::LOG);
    @endif
    @ifdef ( SIP::LOG )
        Log::disable_stream(SIP::LOG);
    @endif
    @ifdef ( Syslog::LOG )
        Log::disable_stream(Syslog::LOG);
    @endif
    }
