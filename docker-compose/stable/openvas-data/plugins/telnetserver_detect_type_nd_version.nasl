###############################################################################
# OpenVAS Vulnerability Test
#
# Telnet Banner Reporting
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2005 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10281");
  script_version("2021-05-04T10:59:20+0000");
  script_tag(name:"last_modification", value:"2021-05-04 10:59:20 +0000 (Tue, 04 May 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Telnet Banner Reporting");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SecuriTeam");
  script_family("Service detection");
  script_dependencies("telnet.nasl");
  script_require_ports("Services/telnet", 23);

  script_tag(name:"summary", value:"This scripts reports the received banner of a Telnet service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("dump.inc");
include("telnet_func.inc");
include("misc_func.inc");

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );

if( strlen( banner ) ) {

  if( "login:" >!< tolower( banner ) ) {
    # nb: For check_account() of default_account.inc
    set_kb_item( name:"telnet/" + port + "/no_login_banner", value:TRUE );
    set_kb_item( name:"telnet/no_login_banner", value:TRUE );
  } else {
    # nb: For VTs which should run against all telnet services having a "login:" banner
    set_kb_item( name:"telnet/" + port + "/login_banner/available", value:TRUE );
    set_kb_item( name:"telnet/login_banner/available", value:TRUE );
  }

  set_kb_item( name:"telnet/banner/available", value:TRUE );
  set_kb_item( name:"ssh_or_telnet/banner/available", value:TRUE );

  # nb: Safeguard if telnet.nasl failed on fragile ports
  if( service_is_unknown( port:port ) )
    service_register( port:port, proto:"telnet", message:"A Telnet server seems to be running on this port" );

  if( "User Access Verification" >< banner && ( "Username:" >< banner || "cisco" >< banner ) ) {
    set_kb_item( name:"telnet/cisco/ios/detected", value:TRUE );
    guess += '\n- Cisco IOS';
  }

  if( "Welcome to ZXDSL 831CII" >< banner ) {
    set_kb_item( name:"telnet/zte/zxdsl_831cii/detected", value:TRUE );
    guess += '\n- ZTE ZXDSL 831CII';
  }

  if( "MikroTik" >< banner && "Login:" >< banner ) {
    set_kb_item( name:"telnet/mikrotik/routeros/detected", value:TRUE );
    guess += '\n- MikroTik RouterOS';
  }

  if( "Huawei TE" >< banner ) {
    set_kb_item( name:"telnet/huawei/te/detected", value:TRUE );
    guess += '\n- Huawei TE Device';
  }

  if( "HP JetDirect" >< banner ) {
    set_kb_item( name:"telnet/hp/jetdirect/detected", value:TRUE );
    guess += '\n- HP JetDirect Device';
  }

  if( "IQinVision " >< banner ) {
    set_kb_item( name:"telnet/vicon_industries/network_camera/detected", value:TRUE );
    guess += '\n- Vicon Industries Network Camera';
  }

  if( "Broadband Satellite" >< banner && "Hughes Network Systems" >< banner ) {
    set_kb_item( name:"telnet/hughes_network_systems/broadband_satellite_modem/detected", value:TRUE );
    guess += '\n- Hughes Broadband Satellite Modem';
  }

  if( "VxWorks login:" >< banner ) {
    set_kb_item( name:"telnet/vxworks/detected", value:TRUE );
    guess += '\n- VxWorks Embedded Device';
    fragile =  '\n\nNote: Some specific variants of this service (e.g. running on Kronos 4500) are known to be "fragile" or slow to ';
    fragile += 'respond. If you don\'t get any results for this service please consider to:';
    fragile += '\n- raise the "time_between_request" scanner preference';
    fragile += '\n- add "Services/telnet, ' + port + '" to the "non_simult_ports" scanner preference';
  }

  if( "Welcome to NetLinx" >< banner ) {
    set_kb_item( name:"telnet/netlinx/detected", value:TRUE);
    guess += '\n- NetLinx Controller';
  }

  if( banner =~ "Model name\s*:\s*MiiNePort " ) {
    set_kb_item( name:"telnet/moxa/miineport/detected", value:TRUE );
    guess += '\n- Moxa MiiNePort';
  }

  if( banner =~ "Model name\s*:\s*MGate " ) {
    set_kb_item( name:"telnet/moxa/mgate/detected", value:TRUE );
    guess += '\n- Moxa MGate';
  }

  if( "Please keyin your password" >< banner && banner !~ "MiiNePort" && banner !~ "MGate" && eregmatch( pattern:'Model name\\s*:\\s(NPort )?([^ \r\n]+)', string:banner ) ) {
    set_kb_item( name:"telnet/moxa/nport/detected", value:TRUE );
    guess += '\n- Moxa NPort';
  }

  if( "Welcome to V" >< banner && ( "VibNode" >< banner || "VIBNODE" >< banner ) ) {
    set_kb_item( name:"telnet/pruftechnik/vibnode/detected", value:TRUE );
    guess += '\n- PRUFTECHNIK VIBNODE';
  }

  if( "WAC" >< banner && "Foxit Software" >< banner ) {
    set_kb_item( name:"telnet/foxit/wac-server/detected", value:TRUE );
    set_kb_item( name:"ssh_or_telnet/foxit/wac-server/detected", value:TRUE );
    guess += '\n- Foxit Software WAC Server';
  }

  if( "Model: ZNID-GPON" >< banner ) {
    set_kb_item( name:"telnet/zhone/znid_gpon/detected", value:TRUE );
    guess += '\n- ZHONE ZNID GPON Device';
  }

  # nb: See the comment about the device name in gb_netgear_prosafe_telnet_detect.nasl
  if( "User:" >< banner && ( "(GSM7224V2)" >< banner || "(GSM7224)" >< banner ) ) {
    set_kb_item( name:"telnet/netgear/prosafe/detected", value:TRUE );
    guess += '\n- NETGEAR ProSAFE Device';
  }

  if( "Hirschmann Automation and Control GmbH" >< banner ) {
    set_kb_item( name:"telnet/hirschmann/device/detected", value:TRUE );
    guess += '\n- Hirschmann Device';
  }

  if( "Rugged Operating System" >< banner || "Command Line Interface RUGGEDCOM" >< banner ) {
    set_kb_item( name:"telnet/siemens/ruggedcom/detected", value:TRUE );
    guess += '\n- Siemens Rugged Operating System/RUGGEDCOM';
  }

  if( "SIMATIC NET" >< banner || "SCALANCE" >< banner ) {
    set_kb_item( name:"telnet/siemens/scalance/detected", value:TRUE );
    guess += '\n- Siemens SIMATIC SCALANCE Device';
  }

  if( banner =~ "U1900 OS.*on eSpace" ) {
    set_kb_item( name:"telnet/huawei/espace/detected", value:TRUE );
    guess += '\n- Huawei eSpace Unified Gateway';
  }

  if( "Fabric OS" >< banner ) {
    set_kb_item( name:"telnet/brocade/fabric_os/detected", value:TRUE );
    guess += '\n- Brocade Fabric OS';
  }

  if( banner =~ 'Autonomic Controls' ) {
    set_kb_item( name:"telnet/autonomic_controls/device/detected", value:TRUE );
    guess += '\n- Autonomic Controls Device';
  }

  if( banner =~ '(Shield|Power)Link' ) {
    set_kb_item( name:"telnet/ecessa/shield_power_link/detected", value:TRUE );
    guess += '\n- Ecessa ShieldLink/PowerLink';
  }

  if( "Telemetry Gateway A840" >< banner ) {
    set_kb_item( name:"telnet/adcon/telemetry_gateway_a840/detected", value:TRUE );
    guess += '\n- Adcon A840 Telemetry Gateway';
  }

  if( "Huawei DP300" >< banner ) {
    set_kb_item( name:"telnet/huawei/dp300/detected", value:TRUE );
    guess += '\n- Huawei DP300';
  }

  if( "Bay Networks" >< banner || ( "Passport" >< banner || "NetLogin:" >< banner ) ) {
    set_kb_item( name:"telnet/nortel_bay_networks/device/detected", value:TRUE );
    guess += '\n- Nortel Networks (former Bay Networks) Device';
  }

  if( "Annex" >< banner ) {
    set_kb_item( name:"telnet/nortel_bay_networks/annex/detected", value:TRUE );
    guess += '\n- Nortel Networks (former Bay Networks) Annex';
  }

  if( "@ Userid:" >< banner ) {
    set_kb_item( name:"telnet/shiva/lanrover/detected", value:TRUE );
    guess += '\n- Shiva LanRover';
  }

  if( "Accelar 1200" >< banner ) {
    set_kb_item( name:"telnet/bay_networks/accelar_1200/detected", value:TRUE );
    guess += '\n- Bay Networks Accelar 1200 Switch';
  }

  if( "Ctrl-Y" >< banner || "P Configuration" >< banner ) {
    set_kb_item( name:"telnet/nortel_networks/baystack/detected", value:TRUE );
    guess += '\n- Nortel Baystack Switch';
  }

  if( "Welcome to P330" >< banner ) {
    set_kb_item( name:"telnet/avaya_p330/detected", value:TRUE );
    guess += '\n- Avaya P330 Stackable Switch';
  }

  if( "TELNET session" >< banner ) {
    set_kb_item( name:"telnet/allied/telesyn/detected", value:TRUE );
    guess += '\n- Allied Telesyn Router/Switch';
  }

  if( banner =~ "GE.*SNMP/Web Interface" && "UPS" >< banner ) {
    set_kb_item( name:"telnet/ge/snmp_web_iface_adapter/detected", value:TRUE );
    guess += '\n- GE SNMP/Web Interface Adapter';
  }

  if( banner =~ "SoftCo OS" ) {
    set_kb_item( name:"telnet/huawei/softco/detected", value:TRUE );
    guess += '\n- Huawei SoftCo';
  }

  if( "Welcome to Microsoft Telnet Service" >< banner ) {
    set_kb_item( name:"telnet/microsoft/telnet_service/detected", value:TRUE );
    guess += '\n- Microsoft Windows Telnet Service';
  }

  if( "KERI-ENET" >< banner ) {
    set_kb_item( name:"telnet/keri_systems/access_control_system/detected", value:TRUE );
    guess += '\n- Keri Systems Access Control System';
  }

  if( "izon login" >< banner ) {
    set_kb_item( name:"telnet/izon/ip_camera/detected", value:TRUE );
    guess += '\n- IZON IP Camera';
  }

  if( "SCALANCE X200" >< banner ) {
    set_kb_item( name:"telnet/siemens/scalance_x200/detected", value:TRUE );
    guess += '\n- Siemens Scalance X200';
  }

  if( "Blackboard LC3000" >< banner ) {
    set_kb_item( name:"telnet/blackboard/lc3000/detected", value:TRUE );
    guess += '\n- Blackboard LC3000 Laundry Reader';
  }

  if( "insight login" >< banner ) {
    set_kb_item( name:"telnet/philips/in_sight/detected", value:TRUE );
    guess += '\n- Philips In.Sight';
  }

  if( "Welcome. Type <return>, enter password at # prompt" >< banner ) {
    set_kb_item( name:"telnet/brother/device/detected", value:TRUE );
    guess += '\n- Multiple Brother Devices';
  }

  if( "ZEM" >< banner ) {
    set_kb_item( name:"telnet/fingertex/device/detected", value:TRUE );
    guess += '\n- FingerTec Device';
  }

  if( "Polycom Command Shell" >< banner || "Welcome to ViewStation" >< banner || ( "Hi, my name is" >< banner && "Here is what I know about myself" >< banner ) ) {
    set_kb_item( name:"telnet/polycom/device/detected", value:TRUE );
    guess += '\n- Polycom Device';
  }

  if( "PK5001Z login:" >< banner || "BCM963268 Broadband Router" >< banner ) {
    set_kb_item( name:"telnet/zyxel/modem/detected", value:TRUE );
    guess += '\n- ZyXEL PK5001Z or C1100Z Modem';
  }

  if( "===Actiontec xDSL Router===" >< banner ) {
    set_kb_item( name:"telnet/actiontec/modem/detected", value:TRUE );
    guess += '\n- Actiontec Modem';
  }

  if( banner =~ "Welcome to (ZXUN|ZXR10).+ of ZTE Corporation" ) {
    set_kb_item( name:"telnet/zte/zxr10/detected", value:TRUE );
    guess += '\n- ZTE ZXR10 Router';
  }

  if( "ManageUPSnet" >< banner ) {
    set_kb_item( name:"telnet/manageupsnet/detected", value:TRUE );
    guess += '\n- ManageUPSNET UPS / USV';
  }

  if( "TANDBERG Codec Release" >< banner ) {
    set_kb_item( name:"telnet/tandberg/device/detected", value:TRUE );
    guess += '\n- Tandberg Device';
  }

  if( "Netsynt " >< banner ) {
    set_kb_item( name:"telnet/netsynt/crd_voice_router/detected", value:TRUE );
    guess += '\n- Netsynt CRD Voice Router';
  }

  if( "pCOWeb login" >< banner ) {
    set_kb_item( name:"telnet/carel/pcoweb/detected", value:TRUE );
    guess += '\n- CAREL pCOWeb';
  }

  if( "BusyBox" >< banner || "list of built-in commands" >< banner ) {
    set_kb_item( name:"telnet/busybox/console/detected", value:TRUE );
    guess += '\n- BusyBox Telnet Console';
  }

  if( "IPmux-2L" >< banner ) {
    set_kb_item( name:"telnet/ipmux-2l/tdm/detected", value:TRUE );
    guess += '\n- IPmux-2L TDM Pseudowire Access Gateway';
  }

  if( banner == '\r\nToo many users logged in!  Please try again later.\r\n' || banner =~ '^\r\n\r\nData ONTAP' ) {
    set_kb_item( name:"telnet/netapp/data_ontap/detected", value:TRUE );
    guess += '\n- NetApp Data ONTAP';
  }

  if( "Welcome to the DataStream" >< banner ) {
    set_kb_item( name:"telnet/datastream/detected", value:TRUE );
    guess += '\n- DataStream (DS800) Device';
  }

  if( "(none) login: " >< banner ) {
    set_kb_item( name:"telnet/mult_dvr_or_radio/detected", value:TRUE );
    guess += '\n- DVR or Internet Radio Device of multiple vendors (e.g. TELESTAR-DIGITAL GmbH)';
    guess += '\n- HiSilicon Encoder';
  }

  if( "Digitalisierungsbox" >< banner ) {
    set_kb_item( name:"telnet/digitalisierungsbox/detected", value:TRUE );
    guess += '\n- Digitalisierungsbox STANDARD/BASIC/SMART/PREMIUM';
  }

  if( "SmartLAN login:" >< banner ) {
    set_kb_item( name:"telnet/inim/smartlan/detected", value:TRUE );
    guess += '\n- Inim SmartLAN';
  }

  if( "| LANCOM" >< banner ) {
    set_kb_item( name:"telnet/lancom/detected", value:TRUE );
    guess += '\n- LANCOM Device';
  }

  if( "Draytek login:" >< banner ) {
    set_kb_item( name:"telnet/draytek/detected", value:TRUE );
    guess += '\n- DrayTek Vigor Device';
  }

  if( "Grandstream GXP" >< banner ) {
    set_kb_item( name:"telnet/grandstream/gxp/detected", value:TRUE );
    guess += '\n- Grandstream GXP Series IP Phone';
  }

  if( "Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet." >< banner || ( "Login authentication" >< banner && "Username:" >< banner ) ) {
    set_kb_item( name:"telnet/huawei/vrp/detected", value:TRUE );
    guess += '\n- Huawei Versatile Routing Platform (VRP)';
  }

  if( "geneko login:" >< banner ) {
    set_kb_item( name:"telnet/geneko/router/detected", value:TRUE );
    guess += '\n- Geneko Router';
  }

  if( "xlweb login:" >< banner ) {
    set_kb_item( name:"telnet/honeywell/excel_web/detected", value:TRUE );
    guess += '\n- Honeywell Excel Web Controller';
  }

  if( banner =~ "Welcome to (ZyWALL )?USG ?[0-9]+" ) {
    set_kb_item( name:"telnet/zyxel_usg/detected", value:TRUE );
    guess += '\n- Zyxel USG Device';
  }

  report = 'Remote Telnet banner:\n\n' + banner;
  if( strlen( guess ) > 0 )
    report += '\n\nThis is probably (a):\n' + guess;

  if( strlen( fragile ) > 0 )
    report += fragile;

  log_message( port:port, data:report );
}

exit( 0 );
