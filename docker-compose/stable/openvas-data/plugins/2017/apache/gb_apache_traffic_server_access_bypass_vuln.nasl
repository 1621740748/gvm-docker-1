###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Traffic Server (ATS) Access Bypass Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812230");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2015-3249");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-11-29 16:54:52 +0530 (Wed, 29 Nov 2017)");
  script_name("Apache Traffic Server (ATS) Access Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Apache Traffic
  Server and is prone to access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a failure to
  properly tunnel remap requests using CONNECT.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass access restrictions.");

  script_tag(name:"affected", value:"Apache Traffic Server 5.1.x before 5.1.1");

  script_tag(name:"solution", value:"Upgrade to Apache Wicket version 5.1.1
  or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_mandatory_keys("apache_trafficserver/installed");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/TS-2677");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
atsVer = infos['version'];
atsPath = infos['location'];

if(atsVer =~ "^(5\.1)")
{
  if(version_is_less(version: atsVer, test_version: "5.1.1"))
  {
    report = report_fixed_ver(installed_version: atsVer, fixed_version: "5.1.1", install_path:atsPath);
    security_message(port: port, data: report);
    exit(0);
  }
}
exit(0);
