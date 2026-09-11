module DNS_Entropy;

export {
    # Add a new column directly to conn.log
    redef record Conn::Info += {
        dns_query_entropy: double &optional &log;
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    # Zeek's native find_entropy returns an entropy_test_result record
    local entropy_res = find_entropy(query);

    # A single connection can carry more than one DNS query — DNS-over-TCP
    # sessions, or a few UDP queries landing on the same 5-tuple in a short
    # window both do this. Track the MAX entropy seen on the connection
    # rather than just the last query, so a single high-entropy (likely
    # DGA/tunneling) lookup isn't masked by an ordinary one that follows it
    # on the same flow.
    if (!c$conn?$dns_query_entropy || entropy_res$entropy > c$conn$dns_query_entropy) {
        c$conn$dns_query_entropy = entropy_res$entropy;
    }
}
