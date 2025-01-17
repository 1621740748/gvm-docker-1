# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103708");
  script_version("2021-04-16T08:08:22+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-16 08:08:22 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2013-05-08 13:51:27 +0100 (Wed, 08 May 2013)");
  script_name("Kyocera Printer Default / No Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_kyocera_printers_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("kyocera_printer/installed", "kyocera_model");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://www.h-online.com/security/news/item/Report-Thousands-of-embedded-systems-on-the-net-without-protection-1446441.html");

  script_tag(name:"summary", value:"The remote Kyocera Printer is using default or no credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration without requiring authentication.");

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
include("kyocera_printers.inc");

port = http_get_port( default:80 );

model = get_kb_item( "kyocera_model" );
if( ! model ) exit( 0 );

ret = check_ky_default_login( model:model, port:port );

if( ret ) {

  if( ret == 1 ) {
    message = 'It was possible to login into the remote Kyocera ' + model + ' with user "' + ky_last_user + '" and password "' + ky_last_pass + '"\n';
  }
  else if( ret == 2 ) {
    message = 'The remote Kyocera ' + model + ' is not protected by a username and password.\n';
  }

  security_message( port:port, data:message );
  exit( 0 );
}

exit( 99 );
