# Copyright (C) 2017 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851471");
  script_version("2020-01-31T08:23:39+0000");
  script_tag(name:"last_modification", value:"2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-01-17 05:47:49 +0100 (Tue, 17 Jan 2017)");
  script_cve_id("CVE-2016-9634", "CVE-2016-9635", "CVE-2016-9636", "CVE-2016-9807",
                "CVE-2016-9808", "CVE-2016-9810");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for gstreamer-plugins-good (openSUSE-SU-2017:0151-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins-good'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-good fixes the following issues:

  - CVE-2016-9634: Invalid FLIC files could have caused and an out-of-bounds
  write (bsc#1012102)

  - CVE-2016-9635: Invalid FLIC files could have caused and an out-of-bounds
  write (bsc#1012103)

  - CVE-2016-9636: Prevent maliciously crafted flic files from causing
  invalid memory writes (bsc#1012104)

  - CVE-2016-9807: Prevent the reading of invalid memory in
  flx_decode_chunks, leading to DoS (bsc#1013655)

  - CVE-2016-9808: Prevent maliciously crafted flic files from causing
  invalid memory accesses (bsc#1013653)

  - CVE-2016-9810: Invalid files can be used to extraneous unreferences,
  leading to invalid memory access and DoS (bsc#1013663)");

  script_tag(name:"affected", value:"gstreamer-plugins-good on openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:0151-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2")
{

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good", rpm:"gstreamer-plugins-good~1.4.3~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-debuginfo", rpm:"gstreamer-plugins-good-debuginfo~1.4.3~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-debugsource", rpm:"gstreamer-plugins-good-debugsource~1.4.3~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-doc", rpm:"gstreamer-plugins-good-doc~1.4.3~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra", rpm:"gstreamer-plugins-good-extra~1.4.3~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-debuginfo", rpm:"gstreamer-plugins-good-extra-debuginfo~1.4.3~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-32bit", rpm:"gstreamer-plugins-good-32bit~1.4.3~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-debuginfo-32bit", rpm:"gstreamer-plugins-good-debuginfo-32bit~1.4.3~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-32bit", rpm:"gstreamer-plugins-good-extra-32bit~1.4.3~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-debuginfo-32bit", rpm:"gstreamer-plugins-good-extra-debuginfo-32bit~1.4.3~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-lang", rpm:"gstreamer-plugins-good-lang~1.4.3~3.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
