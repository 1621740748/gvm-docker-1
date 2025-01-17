###############################################################################
# OpenVAS Vulnerability Test
#
# Ruby on Rails redirect_to() HTTP Header Injection Vulnerability - Linux
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800144");
  script_version("2020-07-14T14:33:06+0000");
  script_tag(name:"last_modification", value:"2020-07-14 14:33:06 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-5189");
  script_bugtraq_id(32359);
  script_name("Ruby on Rails redirect_to() HTTP Header Injection Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("rails/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://weblog.rubyonrails.org/2008/10/19/response-splitting-risk");
  script_xref(name:"URL", value:"http://www.rorsecurity.info/journal/2008/10/20/header-injection-and-response-splitting.html");

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary HTML or scripting code
  in the context of an affected application or allow Cross Site Request Forgery
  (CSRF), Cross Site Scripting (XSS) and HTTP Request Smuggling Attacks.");

  script_tag(name:"affected", value:"Ruby on Rails Version before 2.0.5 on Linux.");

  script_tag(name:"insight", value:"Input passed to the redirect_to()function is not properly sanitized before
  being used.");

  script_tag(name:"summary", value:"The host is running Ruby on Rails, which is prone to HTTP Header
  Injection Vulnerability.");

  script_tag(name:"solution", value:"Update to version 2.0.5 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
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

if( version_is_less( version: version, test_version: "2.0.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.5", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
