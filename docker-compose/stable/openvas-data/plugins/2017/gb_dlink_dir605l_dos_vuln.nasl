###############################################################################
# OpenVAS Vulnerability Test
#
# D-Link DIR-605L Denial of Service Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/o:d-link:dir-605l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112129");
  script_version("2020-05-15T10:17:31+0000");
  script_tag(name:"last_modification", value:"2020-05-15 10:17:31 +0000 (Fri, 15 May 2020)");
  script_tag(name:"creation_date", value:"2017-11-17 15:56:17 +0100 (Fri, 17 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2017-9675");
  script_bugtraq_id(99084);
  script_name("D-Link DIR-605L 'CVE-2017-9675' Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_mandatory_keys("d-link/dir/fw_version", "d-link/dir/hw_version");

  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-605L/REVB/DIR-605L_REVB_RELEASE_NOTES_v2.08UIBETAB01_EN.pdf");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/145011/D-Link-DIR605L-2.08-Denial-Of-Service.html");

  script_tag(name:"summary", value:"On D-Link DIR-605L devices, firmware before 2.08UIBetaB01 allows
  an unauthenticated GET request to denial the service and trigger a reboot.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Firmware versions 2.08UI and lower contain a bug in the function that handles HTTP GET requests for
  directory paths that can allow an unauthenticated attacker to cause complete denial of service (device reboot). This bug can be triggered
  from both LAN and WAN.");

  script_tag(name:"affected", value:"D-Link DIR-605L firmware 2.08UI and prior.");

  script_tag(name:"solution", value:"Upgrade to version 2.08UIBetaB01 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

# cpe:/o:d-link:dir-605l_firmware:2.06
if (!fw_vers = get_app_version(cpe: CPE, port: port))
  exit(0);

# e.g. B1
if (!hw_vers = get_kb_item("d-link/dir/hw_version"))
  exit(0);

hw_vers = toupper(hw_vers);

if (hw_vers =~ "^B" && version_is_less(version: fw_vers, test_version: "2.08")) {
  report = report_fixed_ver(installed_version: fw_vers, fixed_version: "2.08UIBetaB01", extra: "Hardware revision: " + hw_vers);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
