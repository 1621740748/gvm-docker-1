###############################################################################
# OpenVAS Vulnerability Test
#
# Axis Network Camera Cross-Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/o:axis:2001_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811276");
  script_version("2020-07-29T13:23:57+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-07-29 13:23:57 +0000 (Wed, 29 Jul 2020)");
  script_tag(name:"creation_date", value:"2017-08-07 18:10:07 +0530 (Mon, 07 Aug 2017)");

  script_cve_id("CVE-2017-12413");

  script_name("Axis Network Camera Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Axis 2001 Network Cameras are prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper sanitization
  of input to 'admin.shtml' page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute javascript code in the context of current user.");

  script_tag(name:"affected", value:"Axis Camera model 2100 Network Camera 2.43.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/143657");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_axis_network_cameras_ftp_detect.nasl");
  script_mandatory_keys("axis/camera/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.43")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
