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
  script_oid("1.3.6.1.4.1.25623.1.0.106756");
  script_version("2021-07-27T06:34:05+0000");
  script_tag(name:"last_modification", value:"2021-07-27 06:34:05 +0000 (Tue, 27 Jul 2021)");
  script_tag(name:"creation_date", value:"2017-04-18 14:50:27 +0200 (Tue, 18 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2010-2307", "CVE-2010-4231", "CVE-2015-5688", "CVE-2017-16806", "CVE-2018-7490",
                "CVE-2019-20085", "CVE-2020-5410", "CVE-2020-24571", "CVE-2021-3019");

  script_name("Generic HTTP Directory Traversal (HTTP Web Root Check)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://owasp.org/www-community/attacks/Path_Traversal");

  script_tag(name:"summary", value:"Generic check for HTTP directory traversal vulnerabilities on
  HTTP web root level.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  access paths and directories that should normally not be accessible by a user. This can result in
  effects ranging from disclosure of confidential information to arbitrary code execution.");

  script_tag(name:"affected", value:"The following products are known to be affected by the pattern
  checked in this VT:

  - No CVE: Project Jug

  - CVE-2010-2307: Motorola SURFBoard cable modem SBV6120E

  - CVE-2010-4231: Camtron CMNC-200 Full HD IP Camera and TecVoz CMNC-200 Megapixel IP Camera

  - CVE-2015-5688: Geddy

  - CVE-2017-16806: Ulterius Server

  - CVE-2018-7490: uWSGI

  - CVE-2019-20085: TVT NVMS-1000

  - CVE-2020-5410: Spring Cloud Config

  - CVE-2020-24571: NexusQA NexusDB

  - CVE-2021-3019: ffay lanproxy

  Other products might be affected as well.");

  script_tag(name:"vuldetect", value:"Sends crafted HTTP requests to the Web Root of the remote web
  server and checks the response.");

  script_tag(name:"solution", value:"Contact the vendor for a solution.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  script_timeout(900);

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

depth = get_kb_item("global_settings/dir_traversal_depth");
traversals = traversal_pattern(extra_pattern_list: make_list(""), depth: depth);
files = traversal_files();
count = 0;
max_count = 3;
suffixes = make_list(
  "",
  "%23vt/test", # Spring Cloud Config flaw (CVE-2020-5410) but other environments / technologies might be affected as well
  "%00"); # PHP < 5.3.4 but other environments / technologies might be affected as well

port = http_get_port(default: 80);

foreach traversal (traversals) {
  foreach pattern (keys(files)) {
    file = files[pattern];
    foreach suffix( suffixes ) {
      url = "/" + traversal + file + suffix;
      req = http_get(port: port, item: url);
      # nb: Don't use http_keepalive_send_recv() here as embedded devices which are often vulnerable
      # shows issues when requesting a keepalive connection.
      res = http_send_recv(port: port, data: req);
      if (egrep(pattern: pattern, string: res, icase: TRUE)) {
        count++;
        vuln += http_report_vuln_url(port: port, url: url) + '\n\n';
        vuln += 'Request:\n' + chomp(req) + '\n\nResponse:\n' + chomp(res) + '\n\n\n';
        break; # nb: Reporting one suffix is enough
      }
    }
    if (count >= max_count)
      break; # nb: No need to continue with that much findings
  }
  if (count >= max_count)
    break;
}

if (vuln) {
  report = 'The following affected URL(s) were found (limited to ' + max_count + ' results):\n\n' + chomp(vuln);
  security_message(port: port, data: report);
}

exit(0);