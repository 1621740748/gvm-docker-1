# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.145656");
  script_version("2021-04-07T07:28:15+0000");
  script_tag(name:"last_modification", value:"2021-04-07 07:28:15 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-03-26 02:18:29 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-3449");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL: DoS Vulnerability (CVE-2021-3449) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An OpenSSL TLS server may crash if sent a maliciously
  crafted renegotiation ClientHello message from a client. If a TLSv1.2 renegotiation
  ClientHello omits the signature_algorithms extension (where it was present in the initial
  ClientHello), but includes a signature_algorithms_cert extension then a NULL
  pointer dereference will result, leading to a crash and a denial of service
  attack.

  A server is only vulnerable if it has TLSv1.2 and renegotiation enabled (which
  is the default configuration). OpenSSL TLS clients are not impacted by this
  issue.");

  script_tag(name:"affected", value:"OpenSSL version 1.1.1 through 1.1.1j.");

  script_tag(name:"solution", value:"Update OpenSSL to version 1.1.1k or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20210325.txt");

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

if (version_in_range(version: version, test_version: "1.1.1", test_version2: "1.1.1j")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.1k", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
