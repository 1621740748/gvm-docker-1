###############################################################################
# OpenVAS Vulnerability Test
#
# Ruby on Rails Action View 'render' Directory Traversal Vulnerability (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809355");
  script_version("2020-07-14T14:33:06+0000");
  script_cve_id("CVE-2016-2097");
  script_bugtraq_id(83726);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-14 14:33:06 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"creation_date", value:"2016-10-14 17:09:25 +0530 (Fri, 14 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Ruby on Rails Action View 'render' Directory Traversal Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Ruby on Rails and is
  prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of
  crafted requests to action view, one of the components of action pack.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attackers to read arbitrary files by leveraging an application's unrestricted
  use of the render method.");

  script_tag(name:"affected", value:"Ruby on Rails before 3.2.22.2,
  Ruby on Rails 4.x before 4.1.14.2 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Ruby on Rails 3.2.22.2 or 4.1.14.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3509");
  script_xref(name:"URL", value:"https://groups.google.com/forum/message/raw?msg=rubyonrails-security/ly-IH-fxr_Q/WLoOhcMZIAAJ");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("rails/detected", "Host/runs_unixoide");
  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

VULN = FALSE;

if( version_is_less( version: version, test_version: "3.2.22.2" ) )
{
  fix = "3.2.22.2";
  VULN = TRUE;
}

else if( version =~ "^(4\.)" )
{
  if( version_is_less( version: version, test_version:"4.1.14.2" ) )
  {
    fix = "4.1.14.2";
    VULN = TRUE;
  }
}

if( VULN )
{
  report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
