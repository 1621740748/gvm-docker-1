# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# @brief Returns the CPE of the "best" determined operating system running on the remote host.
#
# @note You need to add a dependency to the VT "os_detection.nasl" for this function.
#
# @return A string containing the CPE of the "best" OS, NULL if it wasn't possible to determine the best one.
#
function os_get_best_cpe() {

  local_var best_os_cpe;

  best_os_cpe = get_kb_item( "HostDetails/OS/BestMatchCPE" );
  if( best_os_cpe )
    return best_os_cpe;

  return NULL;
}

# @brief Returns the name (text form) of the "best" determined operating system running on the remote host.
#
# @return A string containing the name of the "best" OS, NULL if it wasn't possible to determine the best one.
#
function os_get_best_txt() {

  local_var best_os_txt;

  best_os_txt = get_kb_item( "HostDetails/OS/BestMatchTXT" );
  if( best_os_txt )
    return best_os_txt;

  return NULL;
}

# @brief Returns the info if the operating system of the remote host is matching a specified pattern.
#
# @param _FCT_ANON_ARGS[0] The pattern to match against the remote operating system.
#
# @return "yes" if the remote operating system is matching the specified ospattern, "no" not matching or
#         "unknown" in other cases where it wasn't possible to determine the status of the OS.
#
function os_host_runs() {

  local_var ospattern, best_os;

  ospattern = _FCT_ANON_ARGS[0];
  if( ! ospattern )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#os_host_runs" );

  #TBD/TODO: What if "os_get_best_txt" is "better" then "os_get_best_cpe"?
  best_os = os_get_best_cpe();
  if( isnull( best_os ) ) {
    best_os = os_get_best_txt();
    if( isnull( best_os ) )
      return "unknown";
  }

  #nb: update this to include possible cpes and txt (name in text form) from ssh_detect.nasl, gb_ssh_os_detection.nasl, gather-package-list.nasl and other *_os_detection.nasl
  if( "linux" >< tolower( ospattern ) )
    ospattern = '(' + ospattern + '|apc:aos|ubuntu|debian|bsd|opensuse|fedora|suse|red ?hat|centos|mandriva|mandrake|mageia|slackware|conectiva|amazon|oracle|d-link(:| )d|euleros|openeuler|' +
                'turbolinux|gentoo|cisco|apple|fortios|junos|screenos|univention|esx|xen|pan-?os|qnap|synology|greenbone|hyperip|simatic|rugged(_| )operating(_| )system|vibnode|avm(:| )fritz|(my|wd)(_| )cloud|' +
                'intelbras(:| )ncloud|ricoh:iwb|nucleus(_| )rtos|vxworks|chip-rtos|simatic(_| )hmi|ibm(:| )os(/|_)400|novell|rockwell ?automation(:| )(micrologix|powermonitor)|beward|' +
                'tippingpoint(_| )operating(_| )system|data(_| )ontap|(zavio|tp-link|pearl|qsee)(:| )ip(_| )camera|riverbed(_| )optimization(_| )system|synetica(:| )datastream|' +
                'ricoh(:| ).+_firmware|lexmark(:| ).+_firmware|:wlan_controller_ap_firmware|zyxel(:| ).+_firmware|toshiba(:| ).+_firmware|moxa(:| )(edr|iologik)|sangoma(:| )netborder|' +
                'silver(-| )peak(:| )(unity_edgeconnect|nx|vx|unknown_model)_sd-wan_firmware|ewon(:| ).+_firmware|optergy(:| )proton(_| )firmware|digitalisierungsbox|base(_| )station(_| )firmware|' +
                'smartlan(_g_| )firmware|unitronics(_| ).+_firmware|ruckuswireless.+(_| )firmware|ip-ak2(_| )firmware|lancom(:| ).+(_| )firmware|timetools(:| ).+(_| )firmware|' +
                'unraid:unraid|arubanetworks(:| )instant|arubanetworks:.+(_| )firmware|aruba/hpe.+ firmware|sonicwall(:| )|xerox(:| ).+(_| )firmware|moxa(:| ).+(_| )firmware|circontrol(:| )(circarlife|raption)(_| )firmware|' +
                'barracuda(:| )load( )?balancer|grandstream(:| ).+(_| )firmware|huawei.+firmware|draytek(:| ).+(_| )firmware|(isilon|powerscale)(_| )onefs|vicon(_| )industries(:| ).+(_| )firmware|' +
                'auerswald(:| )compact.+firmware|hpe(:| )onboard(_| )administrator(_| )firmware|sophos(:| )sfos|brickcom|xg(:| ).+(_| )firmware|cnpilot.+(_| )firmware|geneko(_| )router|' +
                'cloudgate.+firmware|sato(:| ).+(_| )firmware|konicaminolta(:| ).+(_| )firmware|gpon(:| ).+(_| )firmware|teltonika(:| ).+(_| )firmware|axis(:| ).+(_| )firmware|znid(_| ).*(_| )firmware|' +
                'yealink(:| )(vo)?ip(_| )phone|officeconnect.*firewall(_| )software|phoenix(_| )contact(:| ).+firmware|honeywell(:| ).*controller|buffalo(:| ).+firmware|linksys(:| ).+firmware|' +
                'intel(:| )standard(_| )manageability|mobileiron(:| )(core|sentry)|edgecore(:| )es3526xa|spinetix(:| ).+firmware|ruckus.*(:| )iot(_| )controller|westermo(:| )weos|netgear(:| )|contiki(-| )os|' +
                'nut(/|_)os|ui(:| ).*(_| )firmware|zyxel(:| ).*firmware|loxone(:| )miniserver|abb(:| ).*firmware|schneider(-| )electric(:| )powerlogic|tp-link(:| ).*firmware|photon(_| )os|avtech|' +
                'garrettcom(:| )|siemens(:| ).*firmware|flir(:| )(ax8|neco(_| )platform)(_| )firmware|maipu(:| ).*firmware|ibm(:| )global(_| )console|easyio(:| )|(sma_solar_technology_ag|sma solar sunny)|' +
                'western(_| )digital(:| )my(_| )book(_| )live(_| )firmware|seagate(:| ).*firmware|epson(:| ).+firmware)';

  if( eregmatch( pattern:ospattern, string:best_os, icase:TRUE ) )
    return "yes";

  return "no";
}

# @brief Registers and reports a detected operating system of the remote host.
#
# @param os          The name of the OS to register.
# @param version     The version of the OS to register.
# @param patch       The update- / patch-level of the OS to register.
# @param cpe         The CPE of the OS to register
# @param banner_type The type of the banner where the OS was detected from, e.g "HTTP Banner".
# @param port        The port of the OS to register.
# @param proto       The protocol of the OS to register. Defaults to "tcp" if not passed.
# @param banner      The banner of the OS where the OS was detected from.
# @param desc        The description of the VT (e.g. script_name()) registering the OS
# @param runs_key    The "runs_key" which should be used to register the OS as, currently supported: "windows" or "unixoide".
# @param full_cpe    Flag to determine whether the CPE is fully set and already includes the version and/or patch.
#
# @return NULL
#
function os_register_and_report( os, version, patch, cpe, banner_type, port, proto, banner, desc, runs_key, full_cpe ) {

  local_var os, version, patch, cpe, banner_type, port, proto, banner, desc, runs_key, full_cpe;
  local_var oid, malformed_cpe, report, version_lo, patch_lo;

  oid = get_script_oid();

  if( cpe && ! get_base_cpe( cpe:cpe ) ) {
    set_kb_item( name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#os_register_and_report()#-#" + cpe + "#-#cpe" );
    malformed_cpe = TRUE;
  }

  if( ! proto )
    proto = "tcp";

  if( ! desc )
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#desc#-#os_register_and_report" );

  if( strlen( os ) > 0 ) {
    # nb: The check for "version >!< os" is to avoid that the version number is added if it was
    # already included in the "os" function parameter (shouldn't happen but just to be sure...)
    if( strlen( version ) > 0 && tolower( version ) != "unknown" && version >!< os )
      os += " " + version;

    register_host_detail( name:"OS", value:os, desc:desc );
  } else {
    os = "N/A";
  }

  report = 'OS:           ' + os;

  if( version && tolower( version ) != "unknown" ) {

    version_lo = tolower( version );

    report += '\nVersion:      ' + version;

    if( cpe && ! full_cpe && ! malformed_cpe )
      cpe += ":" + version_lo;
  }

  if( patch && tolower( patch ) != "unknown" ) {

    patch_lo = tolower( patch );

    report += '\nPatch/Update: ' + patch;

    if( cpe && ! full_cpe && ! malformed_cpe ) {
      if( version && tolower( version ) != "unknown" )
        cpe += ":" + patch_lo;
      else
        cpe += "::" + patch_lo;
    }
  }

  if( cpe && ! malformed_cpe )
    register_host_detail( name:"OS", value:cpe, desc:desc );
  else
    cpe = "N/A";

  report += '\nCPE:          ' + cpe;
  report += '\nFound by NVT: ' + oid + ' (' + desc + ')';

  if( banner_type ) {

    report += '\nConcluded from ' + banner_type;

    if( port && proto != "icmp" )
      report += " on port " + port + "/" + proto;

    if( banner ) {
      banner = chomp( banner ); # Few banners have newlines at the end so removing these here
      report += ': ' + banner;
    }
  }

  # Keep down here as we only need this defaults for the set_kb_item
  if( ! port )
    port = "0";

  set_kb_item( name:"os_detection_report/reports/" + oid + "/" + port + "/" + proto, value:report );

  # For setting the "Host/runs_windows" or "Host/runs_unixoide" key in os_detection.nasl
  if( ! isnull( runs_key ) )
    set_kb_item( name:"os_detection_report/host_runs/" + oid + "/" + port + "/" + proto, value:runs_key );
  else
    set_kb_item( name:"os_detection_report/host_runs/" + oid + "/" + port + "/" + proto, value:"unknown" );
}

# @brief Registers an unknown banner in the KB which could contain info to detect an operating
#        system for later reporting within gb_unknown_os_service_reporting.nasl
#
# @param banner            the banner to register. Required.
# @param banner_type_name  short description of the banner (e.g. HTTP banner) which is included
#                          in the later reporting. Required.
# @param banner_type_short short keyword (e.g. http_banner) which is used internally as a keyword
#                          for the KB key where the information is saved at. Required.
# @param port              port (optional) where the banner was identified at, defaults to "0" if empty.
# @param proto             protocol (optional, tcp or udp) where the banner was idenfitied at, defaults
#                          to "tcp" if empty.
#
# @return NULL
#
function os_register_unknown_banner( banner, banner_type_name, banner_type_short, port, proto ) {

  local_var banner, banner_type_name, banner_type_short, port, proto;
  local_var oid;

  oid = get_script_oid();

  if( ! banner ) {
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#banner#-#os_register_unknown_banner" );
    return;
  }

  if( ! banner_type_name ) {
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#banner_type_name#-#os_register_unknown_banner" );
    return;
  }

  if( ! banner_type_short ) {
    set_kb_item( name:"vt_debug_empty/" + oid, value:oid + "#-#banner_type_short#-#os_register_unknown_banner" );
    return;
  }

  banner = chomp( banner ); # Few banners have newlines at the end so removing these here

  # Don't report known banner were we know that it doesn't contain info about an OS here
  if( banner == "login:" ||
      egrep( pattern:"^MikroTik ", string:banner ) || # Already covered by gb_mikrotik_router_routeros_consolidation.nasl
      egrep( pattern:"^[0-9.]+$", string:banner ) ) { # Bind9 and MySQL. Both are often only sending e.g. 9.4.2
    return;
  }

  if( ! proto )
    proto = "tcp";

  if( ! port )
    port = "0";

  set_kb_item( name:"os_detection_report/unknown_os_banner/" + oid + "/" + port + "/" + proto + "/" + banner_type_short + "/banner", value:banner );
  set_kb_item( name:"os_detection_report/unknown_os_banner/" + oid + "/" + port + "/" + proto + "/" + banner_type_short + "/type_full", value:banner_type_name );
  set_kb_item( name:"unknown_os_or_service/available", value:TRUE ); # Used in gb_unknown_os_service_reporting.nasl
}

# @brief Evaluates if the passed list contains at least one element of the same type (cpe or text).
#        TODO: Not really sure what the functions is actually doing / responsible for...
#
# @param oslist A list of operating system CPEs to match against.
# @param bestos The CPE of the current "Best OS" registered.
#
# @return TRUE if the list contains at least one element of the same type (cpe or text), FALSE otherwise.
#
function os_conflict( oslist, bestos ) {

  local_var oslist, bestos, is_cpe, _item;

  is_cpe = FALSE;

  if( "cpe:/" >< bestos )
    is_cpe = TRUE;

  foreach _item( oslist ) {
    if( _item == bestos )
      continue;

    # return true if the list contains at least one element of the same type (cpe or text)
    if( ( "cpe:/" >< _item ) == is_cpe )
      return TRUE;
  }
  return FALSE;
}

# @brief Registers the CPE of the "best" determined operating system running on the remote host as a
#        HostDetail.
#
# @note You need to add a dependency to the VT "os_detection.nasl" for this function.
#
# @return NULL
#
function os_report_best_cpe() {

  local_var best_os_cpe, desc;

  best_os_cpe = os_get_best_cpe();
  if( best_os_cpe ) {
    desc = get_kb_item( "HostDetails/OS/BestMatchCPE/Details" );
    desc = split( desc, sep:";" );
    report_host_detail_single( name:"best_os_cpe", value:best_os_cpe, nvt:desc[0], desc:desc[1] );
  }

  return NULL;
}

# @brief Registers the name (text form) of the "best" determined operating system running on the
#        remote host as a HostDetail.
#
# @note You need to add a dependency to the VT "os_detection.nasl" for this function.
#
# @return NULL
#
function os_report_best_txt() {

  local_var best_os_txt, desc;

  # TODO: In earlier versions of this function it was checked if there is a "os conflict" via a code like e.g.:
  #
  # if( os_conflict( oslist:res, bestos:best_os ) )
  #   best_os = best_os + ' [possible conflict]';
  #
  # Once os_detection.nasl was updated to handle/register multiple OS detections from the same Detection-VT
  # we should re-introduce such a "os_conflict" check again.
  #
  # nb: For some reason src/manage_sql.c of gvmd is only checking for the [possible conflict] text in best_os_txt.
  best_os_txt = os_get_best_txt();
  if( best_os_txt ) {
    desc = get_kb_item( "HostDetails/OS/BestMatchTXT/Details" );
    desc = split( desc, sep:";" );
    report_host_detail_single( name:"best_os_txt", value:best_os_txt, nvt:desc[0], desc:desc[1] );
  }

  return NULL;
}

# @brief Returns the list of OIDs of VTs doing CPE based OS detection. The list is sorted by
#        decreasing accuracy (best is first).
#
# @return The list of OIDs of VTs as described in the function description.
#
function os_get_cpe_src_list() {

  local_var oid_list;

  oid_list = make_list(
    "1.3.6.1.4.1.25623.1.0.103220", # gb_greenbone_os_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105383", # gb_ami_megarac_sp_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103628", # gb_apple_mobile_detect.nasl
    "1.3.6.1.4.1.25623.1.0.810231", # gb_apple_macosx_server_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103418", # gb_vmware_esx_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103417", # gb_vmware_esx_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96206",  # gb_ssh_cisco_ios_get_version.nasl
    "1.3.6.1.4.1.25623.1.0.105544", # gb_cisco_cucmim_version.nasl
    "1.3.6.1.4.1.25623.1.0.105540", # gb_cisco_cucm_version.nasl
    "1.3.6.1.4.1.25623.1.0.105690", # gb_cisco_nx_os_version.nasl
    "1.3.6.1.4.1.25623.1.0.105068", # gb_cyclades_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105313", # gb_fortios_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144208", # gb_fortimail_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105440", # gb_cisco_esa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105441", # gb_cisco_wsa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105433", # gb_cisco_csma_version.nasl
    "1.3.6.1.4.1.25623.1.0.105533", # gb_cisco_ip_phone_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105532", # gb_cisco_ios_xr_version.nasl
    "1.3.6.1.4.1.25623.1.0.146071", # gsf/gb_cisco_sdwan_vedge_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96200",  # gb_ssh_junos_get_version.nasl
    "1.3.6.1.4.1.25623.1.0.105263", # gb_palo_alto_panOS_version.nasl
    "1.3.6.1.4.1.25623.1.0.142605", # gsf/gb_paloalto_globalprotect_portal_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105266", # gb_screenos_version.nasl
    "1.3.6.1.4.1.25623.1.0.106413", # gb_extremeos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108566", # gb_tippingpoint_sms_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.106513", # gb_cisco_asa_version_snmp.nasl
    "1.3.6.1.4.1.25623.1.0.105222", # gb_cisco_asa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105033", # gb_cisco_asa_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145837", # gsf/gb_cisco_meraki_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105430", # gb_cisco_wlc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143118", # gsf/gb_f5_big_iq_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144335", # gsf/gb_secomea_gatemanager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106494", # gb_arista_eos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108307", # gb_netgear_prosafe_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141740", # gb_netgear_wnap_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146185", # gb_netgear_smart_cloud_switch_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107228", # gb_netgear_dgn2200_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112334", # gb_netgear_dgnd3700_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141679", # gb_wd_mybook_live_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108311", # gb_hirschmann_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140590", # gb_phoenix_fl_comserver_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144115", # gb_geneko_router_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143245", # gsf/gb_unitronics_plc_pcom_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144128", # gb_option_cloudgate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.810608", # gb_mikrotik_router_routeros_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.113169", # gb_gpon_home_router_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145096", # gsf/gb_zyxel_usg_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144354", # gb_zhone_znid_gpon_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143523", # gsf/gb_aruba_switches_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141648", # gb_teltonika_router_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106833", # gb_garrettcom_switch_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103710", # gb_3com_officeconnect_vpn_firewall_detect.nasl
    "1.3.6.1.4.1.25623.1.0.810933", # gb_axis_network_cameras_ftp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105144", # gb_xenserver_version.nasl
    "1.3.6.1.4.1.25623.1.0.105659", # gb_cisco_ios_xe_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144170", # gb_cisco_nam_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144402", # gb_cisco_small_business_switch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145983", # gsf/gb_cisco_hyperflex_data_platform_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117529", # gsf/gb_circontrol_circarlife_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117533", # gsf/gb_circontrol_raption_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105625", # gb_sophos_xg_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105626", # gb_sophos_xg_detect_userportal.nasl
    "1.3.6.1.4.1.25623.1.0.105155", # gb_mcafee_email_gateway_version.nasl
    "1.3.6.1.4.1.25623.1.0.140058", # gb_brocade_netiron_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108335", # gb_brocade_fabricos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105244", # gb_arubaos_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146362", # gsf/gb_aruba_instant_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106864", # gb_cyberoam_umt_ngfw_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106875", # gb_aerohive_hiveos_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103875", # gb_qnap_nas_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103786", # gb_synology_dsm_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142078", # gb_drobo_nas_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140995", # gb_buffalo_airstation_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143516", # gb_unraid_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103753", # gb_seagate_blackarmor_nas_detect.nasl
    "1.3.6.1.4.1.25623.1.0.805964", # gb_netsweeper_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.811915", # gb_trendmicro_smart_protection_server_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144022", # gsf/gb_citrix_sharefile_storage_controller_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106151", # gb_barracuda_load_balancer_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142729", # gsf/gb_fortios_sslvpn_portal_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106096", # gb_simatic_s7_version.nasl
    "1.3.6.1.4.1.25623.1.0.140738", # gb_simatic_cp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145830", # gb_simatic_scalance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140811", # gb_siemens_ruggedcom_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142907", # gsf/gb_ewon_flexy_cosy_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143136", # gsf/gb_optergy_proton_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144491", # gb_honeywell_xlweb_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146123", # gsf/gb_schneider_powerlogic_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142369", # gb_easyio_30p_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.20285",  # ilo_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105176", # gb_ibm_gcm_kvm_webinterface_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106078", # gb_watchguard_fireware_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108338", # gb_vibnode_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108347", # gb_hyperip_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143323", # gb_ruckus_unleashed_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143341", # gsf/gb_ruckus_zonedirector_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103910", # gb_avm_fritz_box_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142677", # gb_avm_fritz_wlanrepeater_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143196", # gb_digitalisierungsbox_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143419", # gb_lancom_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143663", # gb_draytek_vigor_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103794", # gb_hp_onboard_administrator_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144339", # gb_cisco_ata_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.106216", # gb_cisco_spa_voip_device_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113281", # gb_yealink_ip_phone_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117074", # gb_dlink_dsr_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.810234", # gb_dlink_dap_detect.nasl
    "1.3.6.1.4.1.25623.1.0.812377", # gb_dlink_dsl_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106015", # gb_dlink_dns_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103689", # gb_dlink_dir_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113293", # gb_dlink_dwr_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144537", # gb_dlink_dcs_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107252", # gb_dgs_1500_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144526", # gb_linksys_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142867", # gb_zyxel_ap_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108488", # gb_wd_mycloud_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112183", # gb_sangoma_nsc_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108491", # gb_intelbras_ncloud_devices_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141923", # gb_netapp_data_ontap_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143673", # gb_emc_isilon_onefs_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112339", # gb_brickcom_network_camera_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142807", # gb_ricoh_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141736", # gb_ricoh_iwb_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142838", # gb_lexmark_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142901", # gb_toshiba_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141824", # gb_xerox_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112774", # gb_sato_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112777", # gsf/gb_konicaminolta_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146406", # gb_epson_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108494", # gb_codesys_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.144306", # gsf/gb_nimbus_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.141684", # gb_simatic_hmi_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141766", # gb_wago_plc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145363", # gsf/gb_abb_ac500_opcua_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141772", # gb_rockwell_micrologix_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142010", # gb_rockwell_powermonitor_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142684", # gsf/gb_crestron_airmedia_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141365", # gb_crestron_cip_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141174", # gb_crestron_ctp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.808203", # gb_sunny_webbox_remote_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145200", # gb_loxone_miniserver_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114075", # gb_beward_ip_camera_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114095", # gb_zavio_ip_cameras_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114097", # gb_tp_link_ip_cameras_detect.nasl
    "1.3.6.1.4.1.25623.1.0.808237", # gb_edgecore_ES3526XA_manager_remote_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114099", # gb_pearl_ip_cameras_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114000", # gb_qsee_ip_camera_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107335", # gb_vicon_industries_network_camera_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105789", # gb_riverbed_steelcentral_version.nasl
    "1.3.6.1.4.1.25623.1.0.106845", # gb_riverbed_steelhead_ssh_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106844", # gb_riverbed_steelhead_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143317", # gsf/gb_sonicwall_email_security_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143539", # gb_dell_sonicwall_sma_sra_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.107120", # gb_dell_sonicwall_gms_detection.nasl
    "1.3.6.1.4.1.25623.1.0.146162", # gsf/gb_sonicwall_nsm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143631", # gb_grandstream_ucm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143704", # gb_grandstream_gxp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140015", # gb_moxa_edr_devices_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143571", # gb_moxa_iologik_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143598", # gb_moxa_mgate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145968", # gb_moxa_nport_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140631", # gb_cambium_cnpilot_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143395", # gsf/gb_honeywell_ip-ak2_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113669", # gsf/gb_auerswald_compact_sip_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108940", # gsf/gb_spinetix_player_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108943", # gsf/gb_spinetix_fusion_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145012", # gsf/gb_contiki_os_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145014", # gsf/gb_ethernut_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106196", # gb_westermo_weos_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145072", # gsf/gb_ui_edgepower_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117491", # gsf/gb_maipu_network_device_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117431", # gsf/gb_flir_ax8_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117449", # gsf/gb_flir_a3xx_series_consolidation.nasl
    # nb: Should be below other FLIR detections because we want to use the FLIR camera firmware
    # version as the OS version if possible.
    "1.3.6.1.4.1.25623.1.0.117452", # gsf/gb_flir_neco_platform_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96207",  # gb_windows_cpe_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112731", # gb_huawei_vrp_network_device_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144459", # gb_huawei_ibmc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.806636", # gb_huawei_VP9660_mcu_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146155", # gb_huawei_home_gateway_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.813817", # gb_avtech_avc7xx_dvr_device_detect.nasl
    "1.3.6.1.4.1.25623.1.0.809066", # gb_avtech_device_detect.nasl
    "1.3.6.1.4.1.25623.1.0.50282",  # gather-package-list.nasl
    "1.3.6.1.4.1.25623.1.0.143355", # gb_huawei_euleros_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105614", # gb_cisco_pis_version.nasl
    "1.3.6.1.4.1.25623.1.0.146019", # gsf/gb_cisco_hyperflex_data_platform_installer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140454", # gb_checkpoint_fw_version.nasl
    "1.3.6.1.4.1.25623.1.0.103621", # gb_smb_windows_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112309", # gb_nec_communication_platforms_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142731", # gsf/gb_tibco_loglogic_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142733", # gsf/gb_inea_me-rtu_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108632", # gsf/gb_mult_vendors_wlan_controller_aps_detection.nasl
    "1.3.6.1.4.1.25623.1.0.142756", # gsf/gb_dell_emc_powerconnect_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142875", # gsf/gb_silverpeak_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143256", # gb_inim_smartlan_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143512", # gsf/gb_timetools_ntp_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143657", # gsf/gb_beckhoff_ads_udp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112771", # gb_dsx_comm_devices_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145540", # gsf/gb_vmware_view_planner_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145934", # gsf/gb_vmware_workspace_one_access_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105862", # gb_vmware_vrealize_operations_manager_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.111015", # sw_f5_firepass_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105303", # gb_f5_enterprise_manager_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105586", # gb_ssh_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.106030", # gb_accellion_fta_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114106", # gsf/gb_synetica_datastream_devices_detect_telnet.nasl
    "1.3.6.1.4.1.25623.1.0.142620", # gsf/gb_cisco_vision_dynamic_signage_director_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142850", # gsf/gb_cisco_ind_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117048", # gsf/gb_cisco_csm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143935", # gb_openvpn_access_server_consolidation.nasl
    # nb: The Proxmox and F5 Enterprise Manager VTs were put after gb_ssh_os_detection.nasl because
    # they might only report a generic Debian/CentOS CPE without including the version which would
    # overwrite the SSH one.
    "1.3.6.1.4.1.25623.1.0.117270", # gb_proxmox_ve_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105305", # gb_f5_enterprise_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113756", # gb_cisco_smi_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144350", # gb_pulse_connect_secure_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144140", # gsf/gb_ibm_spectrum_protect_plus_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144152", # gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103809", # gb_junos_snmp_version.nasl
    "1.3.6.1.4.1.25623.1.0.105271", # gb_citrix_netscaler_version.nasl
    "1.3.6.1.4.1.25623.1.0.810998", # gb_intel_standard_manageability_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144564", # gb_cisco_ucs_director_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144905", # gb_trend_micro_interscan_messaging_security_virtual_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144446", # gsf/gb_vxworks_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144575", # gsf/gb_mobileiron_core_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144573", # gsf/gb_mobileiron_sentry_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103429", # gb_snmp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108014", # gb_dns_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.105355", # gb_ftp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.102011", # smb_nativelanman.nasl
    "1.3.6.1.4.1.25623.1.0.103979", # gb_ucs_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108751", # gb_cwp_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.111067", # sw_http_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.111068", # sw_mail_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.111069", # sw_telnet_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108192", # gb_mysql_mariadb_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.100292", # apcnisd_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140184", # gb_dahua_devices_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108682", # gb_pptp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108590", # gb_ntp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.101013", # remote-detect-MDNS.nasl
    "1.3.6.1.4.1.25623.1.0.10144",  # mssqlserver_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140000", # gb_apple_tv_version.nasl
    "1.3.6.1.4.1.25623.1.0.105899", # gb_apple_tv_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108200", # gb_upnp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108201", # gb_sip_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.140096", # gb_check_mk_agent_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100062", # ms_rdp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143777", # gsf/gb_apache_activemq_jms_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141106", # gb_schneider_clearscada_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107788", # gsf/gb_trendmicro_apex_central_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.118034", # gsf/gb_clickstudios_passwordstate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108044", # dcetest.nasl
    "1.3.6.1.4.1.25623.1.0.103081", # gb_fsecure_internet_gatekeeper_detect.nasl
    "1.3.6.1.4.1.25623.1.0.902058", # secpod_ocs_inventory_ng_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144370", # gsf/gb_symantec_endpoint_protection_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108284", # gb_hnap_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108565", # gb_ident_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108342", # gb_pi-hole_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105569", # gb_citrix_xenmobile_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117275", # gb_dnsmasq_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112869", # gb_dropbear_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141467", # gb_monit_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108451", # gb_rtsp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108455", # gb_nntp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.106220", # gb_siemens_sinema_server_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143411", # gsf/gb_siemens_sppa-t3000_app_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105150", # gb_owa_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103825", # gb_openvas_manager_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103841", # gb_gsa_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144367", # gb_aerospike_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.100870", # gb_artica_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144839", # gsf/gb_ruckus_iot_controller_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144932", # gsf/gb_bigbluebutton_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112850", # gsf/gb_observium_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145038", # gsf/gb_solarwinds_orion_platform_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145045", # gb_microfocus_filr_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145210", # gsf/gb_cisco_dna_center_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146403", # gsf/gb_magicflow_msa_gateway_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145205", # gsf/gb_cisco_smart_software_manager_on_prem_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145436", # gsf/gb_cisco_sdwan_vmanage_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145298", # gsf/gb_apache_druid_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145329", # gb_altn_mdaemon_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145380", # gsf/gb_netmotion_mobility_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145395", # gsf/gb_samsung_wlan_ap_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145444", # gsf/gb_nexusdb_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145481", # gsf/gb_fortilogger_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145485", # gsf/gb_yealink_device_management_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145507", # gsf/gb_inspur_clusterengine_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112873", # gsf/gb_passbolt_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145601", # gsf/gb_netapp_cloud_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117269", # gb_elastix_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145782", # gsf/gb_vmware_workspace_one_access_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117421", # gsf/gb_kemp_loadmaster_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145924", # gsf/gb_voipmonitor_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145929", # gsf/gb_ivanti_avalanche_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145946", # gsf/gb_blackberry_uem_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142006", # gb_solarwinds_orion_npm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146034", # gb_gate_one_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146046", # gsf/gb_tg8_firewall_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146106", # gsf/gb_akkadian_provisioning_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146249", # gsf/gb_dell_wyse_management_suite_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106738", # gb_kaseya_vsa_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146284", # gsf/gb_philips_vue_pacs_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146322", # gsf/gb_philips_vue_motion_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146387", # gsf/gb_elastic_cloud_enterprise_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146413", # gsf/gb_aapanel_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108447", # gb_android_adb_detect.nasl nb: Down here because an ADB service could be run on an Android emulator as well...
    "1.3.6.1.4.1.25623.1.0.10150",  # netbios_name_get.nasl
    "1.3.6.1.4.1.25623.1.0.102002"  # os_fingerprint.nasl
  );

  return oid_list;
}

# @brief Returns the list of OIDs of VTs doing text based OS detection. The list is sorted by
#        decreasing accuracy (best is first).
#
# @return The list of OIDs of VTs as described in the function description.
#
function os_get_txt_src_list() {

  local_var oid_list;

  oid_list = make_list(
    "1.3.6.1.4.1.25623.1.0.103220", # gb_greenbone_os_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105383", # gb_ami_megarac_sp_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103628", # gb_apple_mobile_detect.nasl
    "1.3.6.1.4.1.25623.1.0.810231", # gb_apple_macosx_server_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103418", # gb_vmware_esx_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103417", # gb_vmware_esx_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96206",  # gb_ssh_cisco_ios_get_version.nasl
    "1.3.6.1.4.1.25623.1.0.105544", # gb_cisco_cucmim_version.nasl
    "1.3.6.1.4.1.25623.1.0.105540", # gb_cisco_cucm_version.nasl
    "1.3.6.1.4.1.25623.1.0.105690", # gb_cisco_nx_os_version.nasl
    "1.3.6.1.4.1.25623.1.0.105068", # gb_cyclades_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105313", # gb_fortios_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144208", # gb_fortimail_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105440", # gb_cisco_esa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105441", # gb_cisco_wsa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105433", # gb_cisco_csma_version.nasl
    "1.3.6.1.4.1.25623.1.0.105533", # gb_cisco_ip_phone_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105532", # gb_cisco_ios_xr_version.nasl
    "1.3.6.1.4.1.25623.1.0.146071", # gsf/gb_cisco_sdwan_vedge_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96200",  # gb_ssh_junos_get_version.nasl
    "1.3.6.1.4.1.25623.1.0.105263", # gb_palo_alto_panOS_version.nasl
    "1.3.6.1.4.1.25623.1.0.142605", # gsf/gb_paloalto_globalprotect_portal_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105266", # gb_screenos_version.nasl
    "1.3.6.1.4.1.25623.1.0.106413", # gb_extremeos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108566", # gb_tippingpoint_sms_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.106513", # gb_cisco_asa_version_snmp.nasl
    "1.3.6.1.4.1.25623.1.0.105222", # gb_cisco_asa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105033", # gb_cisco_asa_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145837", # gsf/gb_cisco_meraki_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105430", # gb_cisco_wlc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143118", # gsf/gb_f5_big_iq_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144335", # gsf/gb_secomea_gatemanager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106494", # gb_arista_eos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106875", # gb_aerohive_hiveos_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103875", # gb_qnap_nas_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103786", # gb_synology_dsm_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142078", # gb_drobo_nas_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140995", # gb_buffalo_airstation_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143516", # gb_unraid_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103753", # gb_seagate_blackarmor_nas_detect.nasl
    "1.3.6.1.4.1.25623.1.0.805964", # gb_netsweeper_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.811915", # gb_trendmicro_smart_protection_server_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144022", # gsf/gb_citrix_sharefile_storage_controller_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106151", # gb_barracuda_load_balancer_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142729", # gsf/gb_fortios_sslvpn_portal_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106096", # gb_simatic_s7_version.nasl
    "1.3.6.1.4.1.25623.1.0.140738", # gb_simatic_cp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145830", # gb_simatic_scalance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140811", # gb_siemens_ruggedcom_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142907", # gsf/gb_ewon_flexy_cosy_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143136", # gsf/gb_optergy_proton_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144491", # gb_honeywell_xlweb_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146123", # gsf/gb_schneider_powerlogic_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142369", # gb_easyio_30p_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.20285",  # ilo_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105176", # gb_ibm_gcm_kvm_webinterface_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106078", # gb_watchguard_fireware_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108307", # gb_netgear_prosafe_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141740", # gb_netgear_wnap_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146185", # gb_netgear_smart_cloud_switch_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107228", # gb_netgear_dgn2200_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112334", # gb_netgear_dgnd3700_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141679", # gb_wd_mybook_live_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108311", # gb_hirschmann_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140590", # gb_phoenix_fl_comserver_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144115", # gb_geneko_router_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143245", # gsf/gb_unitronics_plc_pcom_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144128", # gb_option_cloudgate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.810608", # gb_mikrotik_router_routeros_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.113169", # gb_gpon_home_router_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145096", # gsf/gb_zyxel_usg_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144354", # gb_zhone_znid_gpon_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143523", # gsf/gb_aruba_switches_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141648", # gb_teltonika_router_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106833", # gb_garrettcom_switch_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103710", # gb_3com_officeconnect_vpn_firewall_detect.nasl
    "1.3.6.1.4.1.25623.1.0.810933", # gb_axis_network_cameras_ftp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105144", # gb_xenserver_version.nasl
    "1.3.6.1.4.1.25623.1.0.105659", # gb_cisco_ios_xe_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144170", # gb_cisco_nam_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144402", # gb_cisco_small_business_switch_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145983", # gsf/gb_cisco_hyperflex_data_platform_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117529", # gsf/gb_circontrol_circarlife_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117533", # gsf/gb_circontrol_raption_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105625", # gb_sophos_xg_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105626", # gb_sophos_xg_detect_userportal.nasl
    "1.3.6.1.4.1.25623.1.0.105155", # gb_mcafee_email_gateway_version.nasl
    "1.3.6.1.4.1.25623.1.0.140058", # gb_brocade_netiron_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108335", # gb_brocade_fabricos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105244", # gb_arubaos_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146362", # gsf/gb_aruba_instant_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106864", # gb_cyberoam_umt_ngfw_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108338", # gb_vibnode_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108347", # gb_hyperip_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143323", # gb_ruckus_unleashed_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143341", # gsf/gb_ruckus_zonedirector_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103910", # gb_avm_fritz_box_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142677", # gb_avm_fritz_wlanrepeater_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143196", # gb_digitalisierungsbox_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143419", # gb_lancom_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143663", # gb_draytek_vigor_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103794", # gb_hp_onboard_administrator_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144339", # gb_cisco_ata_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.106216", # gb_cisco_spa_voip_device_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113281", # gb_yealink_ip_phone_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117074", # gb_dlink_dsr_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.810234", # gb_dlink_dap_detect.nasl
    "1.3.6.1.4.1.25623.1.0.812377", # gb_dlink_dsl_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106015", # gb_dlink_dns_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103689", # gb_dlink_dir_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113293", # gb_dlink_dwr_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144537", # gb_dlink_dcs_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107252", # gb_dgs_1500_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144526", # gb_linksys_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142867", # gb_zyxel_ap_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108488", # gb_wd_mycloud_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112183", # gb_sangoma_nsc_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108491", # gb_intelbras_ncloud_devices_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141923", # gb_netapp_data_ontap_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143673", # gb_emc_isilon_onefs_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112339", # gb_brickcom_network_camera_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142807", # gb_ricoh_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141736", # gb_ricoh_iwb_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142838", # gb_lexmark_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142901", # gb_toshiba_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141824", # gb_xerox_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112774", # gb_sato_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112777", # gsf/gb_konicaminolta_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146406", # gb_epson_printer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108494", # gb_codesys_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.144306", # gsf/gb_nimbus_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.141684", # gb_simatic_hmi_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141766", # gb_wago_plc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145363", # gsf/gb_abb_ac500_opcua_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141772", # gb_rockwell_micrologix_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142010", # gb_rockwell_powermonitor_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142684", # gsf/gb_crestron_airmedia_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141365", # gb_crestron_cip_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141174", # gb_crestron_ctp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.808203", # gb_sunny_webbox_remote_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145200", # gb_loxone_miniserver_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114075", # gb_beward_ip_cameras_detect_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.114095", # gb_zavio_ip_cameras_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114097", # gb_tp_link_ip_cameras_detect.nasl
    "1.3.6.1.4.1.25623.1.0.808237", # gb_edgecore_ES3526XA_manager_remote_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114099", # gb_pearl_ip_cameras_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114000", # gb_qsee_ip_camera_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107335", # gb_vicon_industries_network_camera_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105789", # gb_riverbed_steelcentral_version.nasl
    "1.3.6.1.4.1.25623.1.0.106845", # gb_riverbed_steelhead_ssh_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106844", # gb_riverbed_steelhead_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143317", # gsf/gb_sonicwall_email_security_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143539", # gb_dell_sonicwall_sma_sra_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.107120", # gb_dell_sonicwall_gms_detection.nasl
    "1.3.6.1.4.1.25623.1.0.146162", # gsf/gb_sonicwall_nsm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143631", # gb_grandstream_ucm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143704", # gb_grandstream_gxp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140015", # gb_moxa_edr_devices_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143571", # gb_moxa_iologik_devices_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143598", # gb_moxa_mgate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145968", # gb_moxa_nport_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140631", # gb_cambium_cnpilot_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143395", # gsf/gb_honeywell_ip-ak2_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113669", # gsf/gb_auerswald_compact_sip_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108940", # gsf/gb_spinetix_player_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108943", # gsf/gb_spinetix_fusion_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145012", # gsf/gb_contiki_os_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145014", # gsf/gb_ethernut_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106196", # gb_westermo_weos_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145072", # gsf/gb_ui_edgepower_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117491", # gsf/gb_maipu_network_device_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117431", # gsf/gb_flir_ax8_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.117449", # gsf/gb_flir_a3xx_series_consolidation.nasl
    # nb: Should be below other FLIR detections because we want to use the FLIR camera firmware
    # version as the OS version if possible.
    "1.3.6.1.4.1.25623.1.0.117452", # gsf/gb_flir_neco_platform_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96207",  # gb_windows_cpe_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112731", # gb_huawei_vrp_network_device_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144459", # gb_huawei_ibmc_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.806636", # gb_huawei_VP9660_mcu_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146155", # gb_huawei_home_gateway_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.813817", # gb_avtech_avc7xx_dvr_device_detect.nasl
    "1.3.6.1.4.1.25623.1.0.809066", # gb_avtech_device_detect.nasl
    "1.3.6.1.4.1.25623.1.0.50282",  # gather-package-list.nasl
    "1.3.6.1.4.1.25623.1.0.143355", # gb_huawei_euleros_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105614", # gb_cisco_pis_version.nasl
    "1.3.6.1.4.1.25623.1.0.146019", # gsf/gb_cisco_hyperflex_data_platform_installer_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140454", # gb_checkpoint_fw_version.nasl
    "1.3.6.1.4.1.25623.1.0.103621", # gb_smb_windows_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112309", # gb_nec_communication_platforms_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142731", # gsf/gb_tibco_loglogic_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142733", # gsf/gb_inea_me-rtu_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108632", # gsf/gb_mult_vendors_wlan_controller_aps_detection.nasl
    "1.3.6.1.4.1.25623.1.0.142756", # gsf/gb_dell_emc_powerconnect_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.142875", # gsf/gb_silverpeak_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143256", # gb_inim_smartlan_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.143512", # gsf/gb_timetools_ntp_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143657", # gsf/gb_beckhoff_ads_udp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112771", # gb_dsx_comm_devices_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145540", # gsf/gb_vmware_view_planner_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145934", # gsf/gb_vmware_workspace_one_access_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105862", # gb_vmware_vrealize_operations_manager_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.111015", # sw_f5_firepass_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105303", # gb_f5_enterprise_manager_ssh_login_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105586", # gb_ssh_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.106030", # gb_accellion_fta_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105271", # gb_citrix_netscaler_version.nasl
    "1.3.6.1.4.1.25623.1.0.810998", # gb_intel_standard_manageability_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144564", # gb_cisco_ucs_director_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144905", # gb_trend_micro_interscan_messaging_security_virtual_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144446", # gsf/gb_vxworks_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144575", # gsf/gb_mobileiron_core_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144573", # gsf/gb_mobileiron_sentry_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.114106", # gsf/gb_synetica_datastream_devices_detect_telnet.nasl
    "1.3.6.1.4.1.25623.1.0.142620", # gsf/gb_cisco_vision_dynamic_signage_director_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142850", # gsf/gb_cisco_ind_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117048", # gsf/gb_cisco_csm_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143935", # gb_openvpn_access_server_consolidation.nasl
    # nb: The Proxmox and F5 Enterprise Manager VTs were put after gb_ssh_os_detection.nasl because
    # they might only report a generic Debian/CentOS CPE without including the version which would
    # overwrite the SSH one.
    "1.3.6.1.4.1.25623.1.0.117270", # gb_proxmox_ve_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105305", # gb_f5_enterprise_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.113756", # gb_cisco_smi_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144350", # gb_pulse_connect_secure_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144140", # gsf/gb_ibm_spectrum_protect_plus_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.144152", # gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.103809", # gb_junos_snmp_version.nasl
    "1.3.6.1.4.1.25623.1.0.103429", # gb_snmp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108014", # gb_dns_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.105355", # gb_ftp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.102011", # smb_nativelanman.nasl
    "1.3.6.1.4.1.25623.1.0.103979", # gb_ucs_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108751", # gb_cwp_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.111067", # sw_http_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.111068", # sw_mail_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.111069", # sw_telnet_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108192", # gb_mysql_mariadb_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.100292", # apcnisd_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140184", # gb_dahua_devices_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108682", # gb_pptp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108590", # gb_ntp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.101013", # remote-detect-MDNS.nasl
    "1.3.6.1.4.1.25623.1.0.10144",  # mssqlserver_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140000", # gb_apple_tv_version.nasl
    "1.3.6.1.4.1.25623.1.0.105899", # gb_apple_tv_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108200", # gb_upnp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108201", # gb_sip_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.140096", # gb_check_mk_agent_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100062", # ms_rdp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143777", # gsf/gb_apache_activemq_jms_detect.nasl
    "1.3.6.1.4.1.25623.1.0.141106", # gb_schneider_clearscada_detect.nasl
    "1.3.6.1.4.1.25623.1.0.107788", # gsf/gb_trendmicro_apex_central_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.118034", # gsf/gb_clickstudios_passwordstate_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108044", # dcetest.nasl
    "1.3.6.1.4.1.25623.1.0.103081", # gb_fsecure_internet_gatekeeper_detect.nasl
    "1.3.6.1.4.1.25623.1.0.902058", # secpod_ocs_inventory_ng_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144370", # gsf/gb_symantec_endpoint_protection_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108284", # gb_hnap_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108565", # gb_ident_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108342", # gb_pi-hole_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105569", # gb_citrix_xenmobile_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117275", # gb_dnsmasq_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.112869", # gb_dropbear_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.141467", # gb_monit_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108451", # gb_rtsp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108455", # gb_nntp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.106220", # gb_siemens_sinema_server_detect.nasl
    "1.3.6.1.4.1.25623.1.0.143411", # gsf/gb_siemens_sppa-t3000_app_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105150", # gb_owa_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103825", # gb_openvas_manager_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103841", # gb_gsa_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144367", # gb_aerospike_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.100870", # gb_artica_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144839", # gsf/gb_ruckus_iot_controller_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.144932", # gsf/gb_bigbluebutton_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112850", # gsf/gb_observium_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145038", # gsf/gb_solarwinds_orion_platform_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145045", # gb_microfocus_filr_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145210", # gsf/gb_cisco_dna_center_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146403", # gsf/gb_magicflow_msa_gateway_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145205", # gsf/gb_cisco_smart_software_manager_on_prem_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145436", # gsf/gb_cisco_sdwan_vmanage_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145298", # gsf/gb_apache_druid_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145329", # gb_altn_mdaemon_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145380", # gsf/gb_netmotion_mobility_server_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145395", # gsf/gb_samsung_wlan_ap_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145444", # gsf/gb_nexusdb_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145481", # gsf/gb_fortilogger_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145485", # gsf/gb_yealink_device_management_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145507", # gsf/gb_inspur_clusterengine_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112873", # gsf/gb_passbolt_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145601", # gsf/gb_netapp_cloud_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117269", # gb_elastix_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145782", # gsf/gb_vmware_workspace_one_access_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.117421", # gsf/gb_kemp_loadmaster_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.145924", # gsf/gb_voipmonitor_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145929", # gsf/gb_ivanti_avalanche_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.145946", # gsf/gb_blackberry_uem_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.142006", # gb_solarwinds_orion_npm_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.146034", # gb_gate_one_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146046", # gsf/gb_tg8_firewall_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146106", # gsf/gb_akkadian_provisioning_manager_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146249", # gsf/gb_dell_wyse_management_suite_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106738", # gb_kaseya_vsa_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146284", # gsf/gb_philips_vue_pacs_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146322", # gsf/gb_philips_vue_motion_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146387", # gsf/gb_elastic_cloud_enterprise_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.146413", # gsf/gb_aapanel_http_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108447", # gb_android_adb_detect.nasl nb: Down here because an ADB service could be run on an Android emulator as well...
    "1.3.6.1.4.1.25623.1.0.10150",  # netbios_name_get.nasl
    "1.3.6.1.4.1.25623.1.0.108021", # gb_nmap_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.102002"  # os_fingerprint.nasl
  );

  return oid_list;
}
