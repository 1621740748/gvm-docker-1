# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117030");
  script_version("2021-03-10T05:21:16+0000");
  script_tag(name:"last_modification", value:"2021-03-10 05:21:16 +0000 (Wed, 10 Mar 2021)");
  script_tag(name:"creation_date", value:"2020-11-06 15:19:32 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2002-0657");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL 0.9.7-beta Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_openssl_consolidation.nasl");
  script_mandatory_keys("openssl/detected");

  script_tag(name:"summary", value:"OpenSSL is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow when Kerberos is enabled allowed attackers to
  execute arbitrary code by sending a long master key.");

  script_tag(name:"affected", value:"OpenSSL version 0.9.7-beta1 to 0.9.7-beta3 when Kerberos is enabled.");

  script_tag(name:"solution", value:"Update to version 0.9.7 or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20020730.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "0.9.7-beta1", test_version2: "0.9.7-beta3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
