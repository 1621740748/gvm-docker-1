# Copyright (C) 2012 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.71310");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3057", "CVE-2011-3058", "CVE-2011-3059", "CVE-2011-3060", "CVE-2011-3061", "CVE-2011-3062", "CVE-2011-3063", "CVE-2011-3064", "CVE-2011-3065");
  script_version("2020-06-03T08:38:58+0000");
  script_tag(name:"last_modification", value:"2020-06-03 08:38:58 +0000 (Wed, 03 Jun 2020)");
  script_tag(name:"creation_date", value:"2012-04-30 07:59:57 -0400 (Mon, 30 Apr 2012)");
  script_name("Gentoo Security Advisory GLSA 201203-24 (chromium v8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been reported in Chromium and V8,
    some of which may allow execution of arbitrary code.");
  script_tag(name:"solution", value:"All Chromium users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/chromium-18.0.1025.142'


All V8 users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/v8-3.8.9.16'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201203-24");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=410045");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2012/03/stable-channel-release-and-beta-channel.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201203-24.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"www-client/chromium", unaffected: make_list("ge 18.0.1025.142"), vulnerable: make_list("lt 18.0.1025.142"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"dev-lang/v8", unaffected: make_list("ge 3.8.9.16"), vulnerable: make_list("lt 3.8.9.16"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
