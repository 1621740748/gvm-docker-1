###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Security Bulletin MS04-017
# Vulnerability in Crystal Reports Web Viewer Could Allow Information Disclosure and Denial of Service
#
# remote-MS00-058.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101003");
  script_version("2020-11-25T11:26:55+0000");
  script_tag(name:"last_modification", value:"2020-11-25 11:26:55 +0000 (Wed, 25 Nov 2020)");
  script_tag(name:"creation_date", value:"2009-03-15 20:49:44 +0100 (Sun, 15 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_bugtraq_id(10260);
  script_cve_id("CVE-2000-0778");
  script_name("Microsoft MS00-058 security check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-058");

  script_tag(name:"solution", value:"Microsoft has released a patch to fix this issue. Please see the
  reference for more information.");

  script_tag(name:"summary", value:"This vulnerability could cause a IIS 5.0 web server to send the
  source code of certain types of web files to a visiting user.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# Asp files the plugin will test
pages = make_list( 'default.asp', 'iisstart.asp', 'localstart.asp' );
matches = make_array( 0, "application/octet-stream", 1, "<% @Language = 'VBScript' %>" );

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

host = http_host_name( port:port );

foreach asp_file( pages ) {

  req = string( 'GET /' + asp_file + ' HTTP/1.0\r\n',
                'Host: ' + host + '\r\n',
                'Translate: f\r\n\r\n' );
  reply = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( reply ) {
    r = tolower( reply );
    content_type = egrep( pattern:"Content-Type", string:r, icase:TRUE );
    if( ( "Microsoft-IIS" >< r ) && ( egrep( pattern:"HTTP/1.[01] 200", string:r, icase:TRUE ) ) && ( matches[0] == content_type ) ) {
      if( egrep( pattern:matches[1], string:r, icase:TRUE ) ) {
        # Report 'Microsoft IIS 'Specialiazed Header' (MS00-058)' Vulnerability
        security_message( port:port );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
