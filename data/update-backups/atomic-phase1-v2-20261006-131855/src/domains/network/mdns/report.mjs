export function mdnsReportView(result={}){
    const metaKeys=['packets_received','queries_sent','query_limit','query_limit_reached','queries_suppressed_by_limit','limited','ipv6_transport'];
    const meta={};for(const key of metaKeys)if(result[key]!==undefined)meta[key]=result[key];
    const reportHosts=(result.report_hosts||[]).map(host=>({
      hostname:host?.hostname??null,
      ipv4_addresses:[...(host?.ipv4_addresses||[])],
      ipv6_addresses:[...(host?.ipv6_addresses||[])],
    }));
    const candidateClassification=basis=>basis==='local_interface'
      ? 'local-interface prefix'
      : basis==='known_route'
        ? 'route-covered candidate range (mask unconfirmed)'
        : basis==='heuristic'
          ? 'heuristic candidate range (mask unknown)'
          : 'candidate range';
    const reportCandidates=(result.report_candidate_networks||[]).map(candidate=>({
      cidr:candidate?.cidr??null,
      family:candidate?.family??null,
      prefix_length:candidate?.prefix_length??null,
      range_start:candidate?.range_start??null,
      range_end:candidate?.range_end??null,
      address_count:String(candidate?.address_count??''),
      basis:candidate?.basis??null,
      classification:candidateClassification(candidate?.basis),
      address_scope:candidate?.address_scope??null,
      actual_subnet_mask_known:candidate?.actual_subnet_mask_known===true,
      observed_host_count:new Set(candidate?.hostnames||[]).size,
      observed_address_count:new Set(candidate?.observed_addresses||[]).size,
    }));
    const outside=(result.evidence||[]).map(item=>({address:item.address,hostname:item.hostname}));
    const none='(none)';
    const host_table_markdown=[
      '| Hostname | IPv4 addresses | IPv6 addresses |',
      '| --- | --- | --- |',
      ...reportHosts.map(host=>`| \`${host.hostname}\` | ${host.ipv4_addresses.length?host.ipv4_addresses.map(x=>`\`${x}\``).join(', '):none} | ${host.ipv6_addresses.length?host.ipv6_addresses.map(x=>`\`${x}\``).join(', '):none} |`),
    ].join('\n');
    const candidate_table_markdown=[
      '| CIDR | Range start | Range end | Address count | Basis | Classification | Scope | Observed hosts |',
      '| --- | --- | --- | ---: | --- | --- | --- | ---: |',
      ...reportCandidates.map(row=>`| \`${row.cidr}\` | \`${row.range_start}\` | \`${row.range_end}\` | \`${row.address_count}\` | ${row.basis} | ${row.classification} | ${row.address_scope} | ${row.observed_host_count} |`),
    ].join('\n');
    return {
      scope:result.scope,
      selected_interface:result.selected_interface,
      status:result.status,
      available:result.available,
      complete:result.complete,
      coverage:result.coverage,
      coverage_limitations:[...(result.coverage_limitations||[])],
      evidence_available:result.evidence_available,
      report_host_count:result.report_host_count??reportHosts.length,
      report_hosts:reportHosts,
      host_table_markdown,
      report_candidate_networks:reportCandidates,
      candidate_table_markdown,
      outside_subnet_advertisements:outside,
      outside_subnet_advertisement_count:outside.length,
      outside_subnet_reason:outside.length?'Only addresses listed in outside_subnet_advertisements may be described as outside-subnet advertisements. They are outside selected-interface subnets and may reflect bridging/reflection, multihoming, or stale advertisements.':null,
      possible_reflection:result.possible_reflection,
      reflector_confirmed:result.reflector_confirmed===true,
      reflection_status:result.reflection_status,
      subnet_masks_advertised:result.subnet_masks_advertised===true,
      scan_performed:result.scan_performed===true,
      reporting_contract:{
        render_all_report_hosts:true,
        expected_host_rows:reportHosts.length,
        copy_host_table_markdown_verbatim:true,
        copy_candidate_table_markdown_verbatim:true,
        preserve_hostname_strings:true,
        preserve_ip_strings:true,
        preserve_address_count_strings:true,
        do_not_abbreviate_ipv6:true,
        do_not_recompute_counts:true,
        candidate_observed_host_count_is_authoritative:true,
        outside_subnet_source:'outside_subnet_advertisements',
        outside_subnet_phrase_requires_membership:true,
        local_subnet_label_requires_basis:'local_interface',
        candidate_classification_is_authoritative:true,
        candidate_basis_language:{
          local_interface:'local-interface prefix',
          known_route:'route-covered candidate range (mask unconfirmed)',
          heuristic:'heuristic candidate range (mask unknown)',
        },
        raw_records_are_audit_only:true,
      },
      raw_audit_evidence_saved:result.raw_audit_evidence_saved===true,
      raw_records_returned:false,
      ...meta,
    };
}
