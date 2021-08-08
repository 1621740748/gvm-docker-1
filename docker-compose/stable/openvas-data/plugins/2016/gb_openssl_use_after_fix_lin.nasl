##############################################################################
# OpenVAS Vulnerability Test
# OpenSSL Use-After-Free Fix vulnerability (Linux)
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107054");
  script_version("2021-03-10T13:54:33+0000");
  script_cve_id("CVE-2016-6309");

  script_tag(name:"last_modification", value:"2021-03-10 13:54:33 +0000 (Wed, 10 Mar 2021)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"creation_date", value:"2016-09-26 06:40:16 +0200 (Mon, 26 Sep 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("OpenSSL Use-After-Free Fix vulnerability (Linux)");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160926.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a Denial of Service (DoS) or a Remote Code Execution (RCE) vulnerability.");

  script_tag(name:"insight", value:"OpenSSL suffers from the possibility of Remote Code Execution or DoS attack after a patch applied to fix
  the 'Use-After-Free' issue which enable attacker to write to the previously freed location.");

  script_tag(name:"impact", value:"Successful exploitation could result in service crash or execution of arbitrary code.");

  script_tag(name:"affected", value:"OpenSSL 1.1.0a.");

  script_tag(name:"solution", value:"OpenSSL 1.1.0 users should upgrade to 1.1.0b.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version:"1.1.0a")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.1.0b", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
