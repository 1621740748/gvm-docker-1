###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71574");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-2089");
  script_version("2020-11-19T10:53:01+0000");
  script_tag(name:"last_modification", value:"2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:55 -0400 (Fri, 10 Aug 2012)");
  script_name("Gentoo Security Advisory GLSA 201206-07 (nginx)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A buffer overflow vulnerability in nginx could result in the
execution of arbitrary code.");
  script_tag(name:"solution", value:"All nginx users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/nginx-1.0.15'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-07");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=411751");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201206-07.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"www-servers/nginx", unaffected: make_list("ge 1.0.15"), vulnerable: make_list("lt 1.0.15"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
