###############################################################################
# OpenVAS Vulnerability Test
#
# OTRS Object Link Restriction Bypass Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803940");
  script_version("2021-07-05T02:00:48+0000");
  script_cve_id("CVE-2013-2625");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-07-05 02:00:48 +0000 (Mon, 05 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-09-25 18:35:59 +0530 (Wed, 25 Sep 2013)");
  script_name("OTRS Object Link Restriction Bypass Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated attacker to view
objects, ticket titles, or edit links to objects.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exists in  object linking mechanism which fails check for access
restrictions.");
  script_tag(name:"solution", value:"Upgrade to OTRS (Open Ticket Request System) version 3.0.19, 3.1.14 and 3.2.4
or later, or apply the patch from the referenced vendor advisory.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with OTRS (Open Ticket Request System) and is prone to
restriction bypass vulnerability.");
  script_tag(name:"affected", value:"OTRS (Open Ticket Request System) version 3.0.x before 3.0.19, 3.1.x before
3.1.14 and 3.2.x before 3.2.4");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52969");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52969");
  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2013-01-en/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OTRS/installed");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(vers = get_app_version(cpe:CPE, port:port))
{
  if(version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.18") ||
     version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.13") ||
     version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.3"))
  {
      security_message(port:port);
      exit(0);
  }

}
