###############################################################################
# OpenVAS Vulnerability Test
#
# Default password 'ibmdb2' for account 'db2as'
#
# Authors:
# Chris Foster
#
# Copyright:
# Copyright (C) 2003 Chris Foster
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11863");
  script_version("2020-08-25T06:55:13+0000");
  script_tag(name:"last_modification", value:"2020-08-25 06:55:13 +0000 (Tue, 25 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0051");
  script_name("Default password 'ibmdb2' for account 'db2as'");
  script_copyright("Copyright (C) 2003 Chris Foster");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "telnet.nasl", "ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The account 'db2as' has the password 'ibmdb2'.");

  script_tag(name:"solution", value:"Set a strong password for this account or disable it.
  This may disable dependent applications so beware.");

  script_tag(name:"impact", value:"An attacker may use it to gain further privileges on this system.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("ssh_func.inc");
include("telnet_func.inc");
include("default_account.inc");
include("misc_func.inc");
include("port_service_func.inc");

account = "db2as";
password = "ibmdb2";

port = check_account( login:account, password:password );
if( port ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
