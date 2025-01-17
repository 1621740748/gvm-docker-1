# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:apache:activemq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142371");
  script_version("2020-04-29T07:58:44+0000");
  script_tag(name:"last_modification", value:"2020-04-29 07:58:44 +0000 (Wed, 29 Apr 2020)");
  script_tag(name:"creation_date", value:"2019-05-06 11:15:16 +0000 (Mon, 06 May 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2019-0222");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache ActiveMQ < 5.15.9 DoS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_apache_activemq_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/activemq/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"In Apache ActiveMQ unmarshalling corrupt MQTT frame can lead to broker Out of
  Memory exception making it unresponsive.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache ActiveMQ 5.0.0 to 5.15.8.");

  script_tag(name:"solution", value:"Upgrade to version 5.15.9 or later.");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.data/CVE-2019-0222-announcement.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.15.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.15.9");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
