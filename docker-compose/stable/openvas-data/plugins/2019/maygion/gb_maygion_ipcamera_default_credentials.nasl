# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114063");
  script_version("2021-06-30T10:23:57+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-30 10:23:57 +0000 (Wed, 30 Jun 2021)");
  script_tag(name:"creation_date", value:"2019-02-04 16:40:45 +0100 (Mon, 04 Feb 2019)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("MayGion IPCamera Default Credentials (HTTP)");
  script_dependencies("gb_maygion_ipcamera_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 81);
  script_mandatory_keys("maygion/ip_camera/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://dariusfreamon.wordpress.com/2013/10/27/sunday-shodan-defaults-3/");

  script_tag(name:"summary", value:"The remote MayGion IP camera is using known default credentials
  for the HTTP login.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of MayGion's IP camera software is lacking a
  proper password configuration, which makes critical information and actions accessible for people
  with knowledge of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks via HTTP if a successful login to the IP camera
  software is possible.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");

CPE = "cpe:/a:maygion:ip_camera";

if(!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(!get_app_location(cpe: CPE, port: port))
  exit(0);

creds = make_array("admin", "admin");

foreach username(keys(creds)) {

  password = creds[username];

  #/login.xml?user=admin&usr=admin&password=admin&pwd=admin
  url = "/login.xml?user=" + username + "&usr=" + username + "&password=" + password + "&pwd=" + password;

  req = http_get_req(port: port, url: url, add_headers: make_array("Cookie", "bRememberMe=0; userLastLogin=; passwordLastLogin="));
  res = http_send_recv(port: port, data: req);

  if("<Result><Success>1</Success>" >< res && "<UserGroup>Admin</UserGroup>" >< res) {
    VULN = TRUE;
    report += '\nusername: "' + username + '", password: "' + password + '"';
  }
}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);