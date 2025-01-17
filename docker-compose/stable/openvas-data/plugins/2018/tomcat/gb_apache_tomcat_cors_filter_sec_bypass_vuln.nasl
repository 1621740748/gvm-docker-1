###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat 'CORS Filter' Setting Security Bypass Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813378");
  script_version("2021-05-26T06:00:13+0200");
  script_cve_id("CVE-2018-8014");
  script_bugtraq_id(104203);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-05-22 12:31:15 +0530 (Tue, 22 May 2018)");
  script_name("Apache Tomcat 'CORS Filter' Setting Security Bypass Vulnerability");

  ## It can reasult in FP if users of the CORS filter will have configured it appropriately
  ## for their environment rather than using it in the default configuration
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because defaults settings
  for the CORS filter provided in Apache Tomcat are insecure and enable
  'supportsCredentials' for all origins.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions and perform unauthorized
  actions. This may aid in further attacks.");

  script_tag(name:"affected", value:"Apache Tomcat versions 9.0.0.M1 to 9.0.8
  Apache Tomcat versions 8.5.0 to 8.5.31
  Apache Tomcat versions 8.0.0.RC1 to 8.0.52
  Apache Tomcat versions 7.0.41 to 7.0.88");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat version 9.0.9,
  8.0.53, 7.0.89 or 8.5.32 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");
  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if(isnull(tomPort = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:tomPort, exit_no_version:TRUE))
  exit(0);

appVer = infos['version'];
path = infos['location'];

if(appVer =~ "^8\.5")
{
  if(version_in_range(version:appVer, test_version: "8.5.0", test_version2: "8.5.31")){
    fix = "8.5.32";
  }
}
else if(appVer =~ "^7\.0")
{
  if(version_in_range(version:appVer, test_version: "7.0.41", test_version2: "7.0.88")){
    fix = "7.0.89";
  }
}
else if(appVer =~ "^8\.0")
{
  if((revcomp(a:appVer, b: "8.0.0.RC1") >= 0) && (revcomp(a:appVer, b: "8.0.53") < 0)){
    fix = "8.0.53";
  }
}
else if(appVer =~ "^9\.0")
{
  if((revcomp(a:appVer, b: "9.0.0.M1") >= 0) && (revcomp(a:appVer, b: "9.0.9") < 0)){
    fix = "9.0.9";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix, install_path:path);
  security_message(port:tomPort, data: report);
  exit(0);
}
exit(0);
