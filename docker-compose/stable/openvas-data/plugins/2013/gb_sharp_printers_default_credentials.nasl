###############################################################################
# OpenVAS Vulnerability Test
#
# Sharp Printer Default Account Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103780");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-09-03 11:51:27 +0100 (Tue, 03 Sep 2013)");
  script_name("Sharp Printer Default Account Authentication Bypass Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_sharp_printer_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sharp_printer/installed");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Sharp Printer is prone to a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to sensitive information
  or modify system configuration without requiring authentication.");

  script_tag(name:"insight", value:"It was possible to login using default or no credentials.");

  script_tag(name:"solution", value:"Change or set a password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("sharp_printers.inc");

port = http_get_port( default:80 );

model = get_kb_item( "sharp_model" );
if( ! model ) exit( 0 );

ret = check_sharp_default_login( model:model, port:port );

if( ret ) {

  if( ret == 1 ) {
    message = 'It was possible to login into the remote Sharp ' + model + ' with user "' + sharp_last_user + '" and password "' + sharp_last_pass + '"\n';
  }
  else if( ret == 2 ) {
    message = 'The remote Sharp ' + model + ' is not protected by a username and password.\n';
  }

  security_message( port:port, data:message );
  exit( 0 );
}

exit( 99 );
