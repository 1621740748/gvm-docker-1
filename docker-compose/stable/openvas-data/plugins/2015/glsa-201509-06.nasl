###############################################################################
# OpenVAS Vulnerability Test
#
# Gentoo Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (C) 2015 Eero Volotinen, http://solinor.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121412");
  script_version("2020-02-28T09:03:19+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:29:03 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2020-02-28 09:03:19 +0000 (Fri, 28 Feb 2020)");
  script_name("Gentoo Security Advisory GLSA 201509-06");
  script_tag(name:"insight", value:"A vulnerability in Git causing Git-compatible clients that access case-insensitive or case-normalizing filesystems to overwrite the .git/config when cloning or checking out a repository, leading to execution of arbitrary commands.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201509-06");
  script_cve_id("CVE-2014-9390");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201509-06");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"dev-vcs/git", unaffected: make_list("ge 1.8.5.6"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-vcs/git", unaffected: make_list("ge 1.9.5"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-vcs/git", unaffected: make_list("ge 2.0.5"), vulnerable: make_list() )) != NULL) {

  report += res;
}
if((res=ispkgvuln(pkg:"dev-vcs/git", unaffected: make_list(), vulnerable: make_list("lt 2.0.5"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
