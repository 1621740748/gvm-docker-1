###############################################################################
# OpenVAS Vulnerability Test
#
# Ruby on Rails 'Safe Buffer' Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802115");
  script_version("2020-07-14T14:33:06+0000");
  script_tag(name:"last_modification", value:"2020-07-14 14:33:06 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_cve_id("CVE-2011-2197");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Ruby on Rails 'Safe Buffer' Cross-Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl");
  script_mandatory_keys("rails/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44789");
  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2011/6/8/potential-xss-vulnerability-in-ruby-on-rails-applications");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Ruby on Rails version 2.x before 2.3.12, 3.0.x before 3.0.8 and
  3.1.x before 3.1.0.rc2.");

  script_tag(name:"insight", value:"The flaw is due to certain methods not properly handling the
  'HTML safe' mark for strings, which can lead to improperly sanitised input being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to Ruby on Rails version 2.3.12 or 3.0.8 or 3.1.0.rc2 or later. Apply the patch for Ruby on Rails versions 3.1.0.rc1, 3.0.7 and 2.3.11.");

  script_tag(name:"summary", value:"This host is running Ruby on Rails and is prone to cross-site
  scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

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

if(version_in_range( version: version, test_version: "2.0", test_version2: "2.3.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.12", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.0", test_version2: "3.0.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0.8", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.1", test_version2: "3.1.0.rc1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"3.1.0.rc2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
