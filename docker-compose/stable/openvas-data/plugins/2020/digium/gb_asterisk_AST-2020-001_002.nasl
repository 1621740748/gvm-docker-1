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

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144900");
  script_version("2020-11-24T09:37:13+0000");
  script_tag(name:"last_modification", value:"2020-11-24 09:37:13 +0000 (Tue, 24 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-06 03:55:58 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2020-28327", "CVE-2020-28242");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Multiple DoS Vulnerabilities (AST-2020-001, AST-2020-002)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Remote crash in res_pjsip_session

  - Outbound INVITE loop on challenge with different nonce");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x, 16.x, 17.x, 18.x and 16.8 Certified Asterisk.");

  script_tag(name:"solution", value:"Upgrade to Version 13.37.1, 16.14.1, 17.8.1, 18.0.1, 16.8-cert5 or later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2020-001.html");
  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2020-002.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^13\.") {
  if (version_is_less(version: version, test_version: "13.37.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.37.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^16\.") {
  if (version =~ "^16\.8cert") {
    if (revcomp(a: version, b: "16.8cert5") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.8-cert5");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "16.14.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.14.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^17\.") {
  if (version_is_less(version: version, test_version: "17.8.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "17.8.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^18\.") {
  if (version_is_less(version: version, test_version: "18.0.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "18.0.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(99);
