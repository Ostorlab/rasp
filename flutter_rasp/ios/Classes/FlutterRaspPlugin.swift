import Flutter
import UIKit

public final class FlutterRaspPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
    private let client = RaspNativeClient()
    private var sink: FlutterEventSink?
    public static func register(with registrar: FlutterPluginRegistrar) {
        let instance = FlutterRaspPlugin()
        let channel = FlutterMethodChannel(name: "flutter_rasp", binaryMessenger: registrar.messenger())
        registrar.addMethodCallDelegate(instance, channel: channel)
        FlutterEventChannel(name: "flutter_rasp/events", binaryMessenger: registrar.messenger()).setStreamHandler(instance)
        instance.client.eventHandler = { [weak instance] event in instance?.sink?(event) }
    }
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        var arguments = call.arguments as? [String: Any] ?? [:]
        for name in ["body", "value"] { if let bytes = arguments[name] as? FlutterStandardTypedData { arguments[name] = bytes.data } }
        client.execute(call.method, arguments: arguments) { value, error in
            if let error = error { result(FlutterError(code: "rasp_error", message: error.localizedDescription, details: nil)) }
            else { result(Self.encode(value)) }
        }
    }
    private static func encode(_ value: Any?) -> Any? {
        if let data = value as? Data { return FlutterStandardTypedData(bytes: data) }
        if let map = value as? [String: Any] { return map.mapValues { encode($0) ?? NSNull() } }
        if let array = value as? [Any] { return array.map { encode($0) ?? NSNull() } }
        return value
    }
    public func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? { sink = events; return nil }
    public func onCancel(withArguments arguments: Any?) -> FlutterError? { sink = nil; return nil }
    public func detachFromEngine(for registrar: FlutterPluginRegistrar) { client.execute("stop", arguments: [:]) { _, _ in }; sink = nil }
}
