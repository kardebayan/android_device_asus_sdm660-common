/*
 * Copyright (C) 2024 The LineageOS Project
 *               2024 Paranoid Android
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "Fingerprint.h"

#include <android-base/logging.h>
#include <android-base/properties.h>

namespace aidl::android::hardware::biometrics::fingerprint {

namespace {
constexpr int MAX_ENROLLMENTS_PER_USER = 5;
constexpr char HW_COMPONENT_ID[] = "fingerprintSensor";
constexpr char HW_VERSION[] = "vendor/model/revision";
constexpr char FW_VERSION[] = "1.01";
constexpr char SERIAL_NUMBER[] = "00000001";
constexpr char SW_COMPONENT_ID[] = "matchingAlgorithm";
constexpr char SW_VERSION[] = "vendor/version/revision";
constexpr int32_t SENSOR_ID = 0;

// Module ids resolve through libhardware's "default" variant fallback, e.g.
// "fingerprint.focaltech" -> /vendor/lib64/hw/fingerprint.focaltech.default.so.
struct LegacyModule {
    const char* id;
    const char* vendor;
};

constexpr char VENDOR_PROP[] = "persist.vendor.runin.fp";
constexpr char VENDOR_UNKNOWN[] = "unkown";  // sic, matches the stock blob

// Only cdfinger ships on both devices, so a module that is absent simply misses.
constexpr LegacyModule kModules[] = {
        {"fingerprint.focaltech", "focaltech"},  // X01BD
        {"fingerprint", "goodix"},               // X00TD
        {"cdfinger.fingerprint", "cdfinger"},
};
}  // namespace

static const uint16_t kVersion = HARDWARE_MODULE_API_VERSION(2, 1);
static Fingerprint* sInstance;

Fingerprint::Fingerprint() : mDevice(openHal()) {
    sInstance = this;  // keep track of the most recent instance
}

Fingerprint::~Fingerprint() {
    ALOGV("~Fingerprint()");
    if (mDevice == nullptr) {
        ALOGE("No valid device");
        return;
    }
    int err;
    if (0 != (err = mDevice->common.close(reinterpret_cast<hw_device_t*>(mDevice)))) {
        ALOGE("Can't close fingerprint module, error: %d", err);
        return;
    }
    mDevice = nullptr;
}

static hw_device_t* openLegacyModule(const LegacyModule& mod) {
    int err;
    const hw_module_t* hw_mdl = nullptr;

    if (0 != (err = hw_get_module(mod.id, &hw_mdl))) {
        ALOGE("Can't open %s HW Module %s, error:%d", mod.vendor, mod.id, err);
        return nullptr;
    }

    if (hw_mdl == nullptr) {
        ALOGE("%s module not valid", mod.vendor);
        return nullptr;
    }

    fingerprint_module_t const* module = reinterpret_cast<const fingerprint_module_t*>(hw_mdl);
    if (module->common.methods->open == nullptr) {
        ALOGE("%s Module has no valid open method", mod.vendor);
        return nullptr;
    }

    hw_device_t* device = nullptr;
    if (0 != (err = module->common.methods->open(hw_mdl, nullptr, &device))) {
        ALOGE("%s Module open failed, error: %d", mod.vendor, err);
        return nullptr;
    }

    return device;
}

fingerprint_device_t* Fingerprint::openHal() {
    int err;
    ALOGD("Opening fingerprint hal library...");

    hw_device_t* device = nullptr;
    const LegacyModule* opened = nullptr;
    for (const auto& mod : kModules) {
        if ((device = openLegacyModule(mod)) != nullptr) {
            opened = &mod;
            break;
        }
    }

    if (opened == nullptr) {
        ALOGE("No valid HW Module found!");
        ::android::base::SetProperty(VENDOR_PROP, VENDOR_UNKNOWN);
        return nullptr;
    }

    ALOGD("%s module is working...", opened->vendor);
    ::android::base::SetProperty(VENDOR_PROP, opened->vendor);

    if (kVersion != device->version) {
        // enforce version on new devices because of HIDL@2.1 translation layer
        ALOGE("Wrong fp version. Expected %d, got %d", kVersion, device->version);
        return nullptr;
    }

    fingerprint_device_t* fp_device = reinterpret_cast<fingerprint_device_t*>(device);

    if (0 != (err = fp_device->set_notify(fp_device, Fingerprint::notify))) {
        ALOGE("Can't register fingerprint module callback, error: %d", err);
        return nullptr;
    }

    return fp_device;
}

void Fingerprint::notify(const fingerprint_msg_t* msg) {
    Fingerprint* thisPtr = sInstance;
    if (thisPtr == nullptr || thisPtr->mSession == nullptr || thisPtr->mSession->isClosed()) {
        ALOGE("Receiving callbacks before a session is opened.");
        return;
    }
    thisPtr->mSession->notify(msg);
}

ndk::ScopedAStatus Fingerprint::getSensorProps(std::vector<SensorProps>* out) {
    std::vector<common::ComponentInfo> componentInfo = {
            {HW_COMPONENT_ID, HW_VERSION, FW_VERSION, SERIAL_NUMBER, "" /* softwareVersion */},
            {SW_COMPONENT_ID, "" /* hardwareVersion */, "" /* firmwareVersion */,
             "" /* serialNumber */, SW_VERSION}};
    common::CommonProps commonProps = {SENSOR_ID, common::SensorStrength::STRONG,
                                       MAX_ENROLLMENTS_PER_USER, componentInfo};

    // The sensor is rear mounted, so no location is reported; the framework falls back to
    // SensorLocationInternal.DEFAULT, which only matters for under-display sensors.
    *out = {{commonProps, FingerprintSensorType::REAR, {}, false /* supportsNavigationGestures */,
             false /* supportsDetectInteraction */, false /* halHandlesDisplayTouches */,
             false /* halControlsIllumination */, std::nullopt}};
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Fingerprint::createSession(int32_t /*sensorId*/, int32_t userId,
                                              const std::shared_ptr<ISessionCallback>& cb,
                                              std::shared_ptr<ISession>* out) {
    CHECK(mSession == nullptr || mSession->isClosed()) << "Open session already exists!";

    mSession = SharedRefBase::make<Session>(mDevice, userId, cb, mLockoutTracker);
    *out = mSession;

    mSession->linkToDeath(cb->asBinder().get());

    return ndk::ScopedAStatus::ok();
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
