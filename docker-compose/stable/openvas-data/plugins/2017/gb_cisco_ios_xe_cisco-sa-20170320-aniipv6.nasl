###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco IOS XE Software IPv6 Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106674");
  script_cve_id("CVE-2017-3850");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("2021-01-26T03:06:23+0000");

  script_name("Cisco IOS XE Software IPv6 Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170320-aniipv6");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Autonomic Networking Infrastructure (ANI) feature of
Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS)
condition.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete input validation on certain crafted
packets. An attacker could exploit this vulnerability by sending a crafted IPv6 packet to a device that is
running a Cisco IOS XE Software release that supports the ANI feature.

A device must meet two conditions to be affected by this vulnerability:

  - The device must be running a version of Cisco IOS XE Software that supports ANI (regardless of whether ANI is
configured)

  - The device must have a reachable IPv6 interface.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause the affected device to reload.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2021-01-26 03:06:23 +0000 (Tue, 26 Jan 2021)");
  script_tag(name:"creation_date", value:"2017-03-21 10:01:15 +0700 (Tue, 21 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xe_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xe/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork:TRUE))
  exit(0);

affected = make_list(
  '3.10.0S',
  '3.10.1S',
  '3.10.1xb.S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.8S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0a.S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.0a.S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5a.S',
  '3.13.6S',
  '3.13.6a.S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1c.S',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.0c.S',
  '3.16.1S',
  '3.16.1a.S',
  '3.16.2S',
  '3.16.2a.S',
  '3.16.2b.S',
  '3.16.3S',
  '3.16.3a.S',
  '3.16.4S',
  '3.16.4a.S',
  '3.16.4b.S',
  '3.16.4d.S',
  '3.16.5S',
  '3.17.0S',
  '3.17.1S',
  '3.17.1a.S',
  '3.17.2S',
  '3.17.3S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0a.S',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1a.SP',
  '3.18.1b.SP',
  '3.18.2S',
  '3.18.3v.S',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.9.0E',
  '3.9.1E');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);