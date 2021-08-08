# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117574");
  script_version("2021-08-02T07:15:33+0000");
  script_tag(name:"last_modification", value:"2021-08-02 07:15:33 +0000 (Mon, 02 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-07-22 12:59:06 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  # Currently commented out as our automatic CVSS correction would lower the CVSS score above.
  #  script_cve_id("CVE-2014-3744", "CVE-2017-14849", "CVE-2017-16877", "CVE-2018-3714", "CVE-2020-35736", "CVE-2021-3223", "CVE-2021-23241");

  script_name("Generic HTTP Directory Traversal (HTTP Web Dirs Check)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://owasp.org/www-community/attacks/Path_Traversal");

  script_tag(name:"summary", value:"Generic check for HTTP directory traversal vulnerabilities on
  each HTTP directory.

  NOTE: Please enable 'Enable generic web application scanning' within the VT 'Global variable
  settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) if you want to run this script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  access paths and directories that should normally not be accessible by a user. This can result in
  effects ranging from disclosure of confidential information to arbitrary code execution.");

  script_tag(name:"affected", value:"The following products are known to be affected by the pattern
  checked in this VT:

  - CVE-2014-3744: st module for Node.js

  - CVE-2017-14849: Node.js

  - CVE-2017-16877: ZEIT Next.js

  - CVE-2018-3714: node-srv node module

  - CVE-2020-35736: Gate One

  - CVE-2021-3223: Node RED Dashboard

  - CVE-2021-23241: MERCUSYS Mercury X18G");

  script_tag(name:"vuldetect", value:"Sends crafted HTTP requests to the each found directory of the
  remote web server and checks the response.");

  script_tag(name:"solution", value:"Contact the vendor for a solution.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  script_timeout(900);

  exit(0);
}

# nb: We also don't want to run if optimize_test is set to "no"
if( get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

depth = get_kb_item( "global_settings/dir_traversal_depth" );
# nb: "" was added here to catch the (normally quite unlikely) case that the file is accessible
# via e.g. http://example.com/foo/etc/passwd
traversals = traversal_pattern( extra_pattern_list:make_list( "" ), depth:depth );
files = traversal_files();
count = 0;
max_count = 3;
suffixes = make_list(
  "",
  "%23vt/test", # Spring Cloud Config flaw (CVE-2020-5410) but other environments / technologies might be affected as well
  "%00" ); # PHP < 5.3.4 but other environments / technologies might be affected as well

port = http_get_port( default:80 );

dirs = make_list_unique(
  "/loginLess", # MERCUSYS Mercury X18G
  "/downloads", # Gate One
  "/public", # st module for Node.js
  "/static", # Node.js
  "/_next", # ZEIT Next.js
  "/node_modules", # node-srv node module
  "/ui_base/js", # Node RED Dashboard
  http_cgi_dirs( port:port ) );

foreach dir( dirs ) {

  if( dir == "/" )
    continue; # nb: Already checked in 2017/gb_generic_http_web_root_dir_trav.nasl

  dir_vuln = FALSE; # nb: Used later to only report each dir only once
  foreach traversal( traversals ) {
    foreach pattern( keys( files ) ) {
      file = files[pattern];
      foreach suffix( suffixes ) {
        url = dir + "/" + traversal + file + suffix;
        req = http_get( port:port, item:url );
        res = http_keepalive_send_recv( port:port, data:req );
        if( egrep( pattern:pattern, string:res, icase:TRUE ) ) {
          count++;
          dir_vuln = TRUE;
          vuln += http_report_vuln_url( port:port, url:url ) + '\n\n';
          vuln += 'Request:\n' + chomp( req ) + '\n\nResponse:\n' + chomp( res ) + '\n\n\n';
          break; # Don't report multiple vulnerable pattern / suffixes for the very same dir
        }
      }
      if( count >= max_count || dir_vuln )
        break; # nb: No need to continue with that much findings or with multiple vulnerable pattern / suffixes for the very same dir
    }
    if( count >= max_count || dir_vuln )
      break;
  }
  if( count >= max_count )
    break;
}

if( vuln ) {
  report = 'The following affected URL(s) were found (limited to ' + max_count + ' results):\n\n' + chomp( vuln );
  security_message( port:port, data:report );
}

exit( 0 );