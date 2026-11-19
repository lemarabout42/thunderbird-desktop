/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import { Assert } from "resource://testing-common/Assert.sys.mjs";
import { MockRegistrar } from "resource://testing-common/MockRegistrar.sys.mjs";
import { PrefUtils } from "moz-src:///toolkit/modules/PrefUtils.sys.mjs";

const mailSystemAlertPref = "mail.biff.use_system_alert";
const mockIDs = [];
let savedMailSystemAlert;

export const MockAlertsService = {
  /**
   * The alert most recently passed to `showAlert`.
   *
   * @type {nsIAlertNotification}
   */
  alert: null,

  /**
   * The alert listener most recently passed to `showAlert`.
   *
   * @type {nsIObserver}
   */
  listener: null,

  /**
   * A deferred Promise that resolves when `showAlert` is called.
   *
   * @type {PromiseWithResolvers}
   */
  _shownDeferred: null,

  /**
   * A deferred Promise that resolves when `closeAlert` is called.
   *
   * @type {PromiseWithResolvers}
   */
  _closedDeferred: null,

  /**
   * Route notifications to the mock until cleanup restores the services and
   * preference lock.
   */
  init() {
    const mock = new MockAlertsServiceInstance();
    mockIDs.push(
      MockRegistrar.register("@mozilla.org/system-alerts-service;1", mock)
    );
    if (Services.prefs.prefIsLocked("alerts.useSystemBackend")) {
      mockIDs.push(
        MockRegistrar.register("@mozilla.org/alerts-service;1", mock)
      );
    }

    // Route new mail to the mock while the Windows service is replaced.
    if (Services.prefs.prefIsLocked(mailSystemAlertPref)) {
      Services.prefs.unlockPref(mailSystemAlertPref);
      savedMailSystemAlert = PrefUtils.getPrefStrict(
        mailSystemAlertPref,
        "user"
      );
      Services.prefs.setBoolPref(mailSystemAlertPref, true);
    }
  },

  /**
   * Unregister the mock alerts service with XPCOM.
   */
  cleanup() {
    if (savedMailSystemAlert !== undefined) {
      PrefUtils.setPref(mailSystemAlertPref, savedMailSystemAlert);
      Services.prefs.lockPref(mailSystemAlertPref);
      savedMailSystemAlert = undefined;
    }
    for (const id of mockIDs) {
      MockRegistrar.unregister(id);
    }
    mockIDs.length = 0;
    this.reset();
  },

  /**
   * Forget previous alerts and reject any open Promises.
   */
  reset() {
    this.alert = null;
    this.listener = null;
    this._shownDeferred?.reject(new Error("Cleaning up for new scenario"));
    this._shownDeferred = null;
    this._closedDeferred?.reject(new Error("Cleaning up for new scenario"));
    this._closedDeferred = null;
  },

  /**
   * Get a Promise that resolves when `showAlert` is called.
   *
   * @returns {Promise}
   */
  promiseShown() {
    if (this.alert) {
      return Promise.resolve();
    }
    if (!this._shownDeferred) {
      this._shownDeferred = Promise.withResolvers();
    }
    return this._shownDeferred.promise;
  },

  /**
   * Get a Promise that resolves when `closeAlert` is called.
   *
   * @returns {Promise}
   */
  promiseClosed() {
    if (!this._closedDeferred) {
      this._closedDeferred = Promise.withResolvers();
    }
    return this._closedDeferred.promise;
  },

  /**
   * Simulate a click on a shown alert.
   *
   * @param {string} [actionToClick] - The name of the action button to "click"
   *   if given, otherwise the alert itself is "clicked".
   */
  clickAlert(actionToClick) {
    let action = null;
    if (typeof actionToClick == "string") {
      action = this.alert.actions.find(a => a.action == actionToClick);
      Assert.ok(action, "expected action should be defined");
    }

    this.listener?.observe(action, "alertclickcallback", this.alert.cookie);
    this.callbacks?.onAlertClick(action);
  },
};

/** @implements {nsIAlertsService} */
class MockAlertsServiceInstance {
  QueryInterface = ChromeUtils.generateQI(["nsIAlertsService"]);

  showAlert(alert, listener) {
    dump(`showAlert: ${alert.text ?? alert.title}\n`);
    Assert.ok(
      !MockAlertsService.alert,
      "showAlert should not be called while an alert is showing"
    );
    MockAlertsService.alert = alert;
    MockAlertsService.listener = listener;
    MockAlertsService._shownDeferred?.resolve();
  }

  showAlertWithCallbacks(alert, alertCallbacks) {
    dump(`showAlertWithCallbacks: ${alert.text ?? alert.title}\n`);
    Assert.ok(
      !MockAlertsService.alert,
      "showAlert should not be called while an alert is showing"
    );
    MockAlertsService.alert = alert;
    MockAlertsService.callbacks = alertCallbacks;
    MockAlertsService._shownDeferred?.resolve();
  }

  closeAlert(name) {
    dump(`closeAlert: ${name}\n`);
    if (MockAlertsService._closedDeferred) {
      if (name == MockAlertsService.alert.name) {
        MockAlertsService.listener?.observe(
          null,
          "alertfinished",
          MockAlertsService.alert.cookie
        );
        MockAlertsService._closedDeferred?.resolve();
      }
    }
  }

  getHistory() {
    Assert.ok(false, "unexpected call to getHistory");
  }

  teardown() {
    if (!Services.startup.shuttingDown) {
      Assert.ok(false, "unexpected call to teardown");
    }
  }

  pbmTeardown() {
    Assert.ok(false, "unexpected call to pbmTeardown");
  }
}
