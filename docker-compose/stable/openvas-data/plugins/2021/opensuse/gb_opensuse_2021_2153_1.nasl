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
  script_oid("1.3.6.1.4.1.25623.1.0.853927");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2021-33516");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-07-23 08:38:39 +0000 (Fri, 23 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-13 03:03:32 +0000 (Tue, 13 Jul 2021)");
  script_name("openSUSE: Security Advisory for gupnp (openSUSE-SU-2021:2153-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2153-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CWMAQ7IJUIENIJYPPEUVGYSZ473DP5EV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gupnp'
  package(s) announced via the openSUSE-SU-2021:2153-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gupnp fixes the following issues:

  - CVE-2021-33516: Fixed a DNS rebinding, which could trick the browser
       into triggering actions against local UPnP services (bsc#1186590).");

  script_tag(name:"affected", value:"'gupnp' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"gupnp-debugsource", rpm:"gupnp-debugsource~1.2.2~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgupnp-1_2-0", rpm:"libgupnp-1_2-0~1.2.2~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgupnp-1_2-0-debuginfo", rpm:"libgupnp-1_2-0-debuginfo~1.2.2~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgupnp-devel", rpm:"libgupnp-devel~1.2.2~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GUPnP-1_0", rpm:"typelib-1_0-GUPnP-1_0~1.2.2~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgupnp-1_2-0-32bit", rpm:"libgupnp-1_2-0-32bit~1.2.2~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgupnp-1_2-0-32bit-debuginfo", rpm:"libgupnp-1_2-0-32bit-debuginfo~1.2.2~3.3.1", rls:"openSUSELeap15.3"))) {
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