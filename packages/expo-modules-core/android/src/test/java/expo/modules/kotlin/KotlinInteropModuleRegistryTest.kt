package expo.modules.kotlin

import com.facebook.react.bridge.JavaOnlyArray
import com.facebook.react.bridge.JavaOnlyMap
import com.google.common.truth.Truth
import expo.modules.PromiseMock
import expo.modules.PromiseState
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import io.mockk.mockk
import org.junit.Test
import java.lang.ref.WeakReference

private class TestException : CodedException("Something went wrong")

private class TestRecord : Record {
  @Field
  lateinit var string: String
}

private class TestModule_1 : Module() {
  override fun definition() = ModuleDefinition {
    name("test-1")
    function("f1") {
      throw NullPointerException()
    }
    function<Int, TestRecord>("f2") {
      throw NullPointerException()
    }
    constants {
      mapOf(
        "c1" to 123,
        "c2" to "123"
      )
    }
  }
}

private class TestModule_2 : Module() {
  override fun definition() = ModuleDefinition {
    name("test-2")
    function("f1") {
      throw TestException()
    }
    function("f2") { arg1: Int ->
      arg1
    }
    viewManager {
      view { mockk() }
    }
  }
}

private val provider = object : ModulesProvider {
  override fun getModulesList(): List<Class<out Module>> {
    return listOf(
      TestModule_1::class.java,
      TestModule_2::class.java
    )
  }
}

class KotlinInteropModuleRegistryTest {
  private val interopModuleRegistry = KotlinInteropModuleRegistry(
    provider,
    mockk(),
    WeakReference(mockk(relaxed = true))
  )

  @Test
  fun `should register modules from provider`() {
    interopModuleRegistry.hasModule("test-1")
    interopModuleRegistry.hasModule("test-2")
  }

  @Test
  fun `should export constants`() {
    Truth.assertThat(interopModuleRegistry.exportedModulesConstants())
      .containsAtLeast(
        "test-1", mapOf("c1" to 123, "c2" to "123"),
        "test-2", emptyMap<String, Any>()
      )
  }

  @Test
  fun `should export view manages`() {
    val rnManagers = interopModuleRegistry.exportViewManagers()
    val expoManagersNames = interopModuleRegistry.exportedViewManagersNames()

    Truth.assertThat(rnManagers).hasSize(1)
    Truth.assertThat(rnManagers.first().name).isEqualTo("ViewManagerAdapter_test-2")
    Truth.assertThat(expoManagersNames).containsExactly("test-2")
  }

  @Test
  fun `call method should reject if something goes wrong`() {
    val mockedPromise = PromiseMock()
    val mockedPromise2 = PromiseMock()

    interopModuleRegistry.callMethod("test-1", "f1", JavaOnlyArray(), mockedPromise)
    interopModuleRegistry.callMethod("test-2", "f1", JavaOnlyArray(), mockedPromise2)

    Truth.assertThat(mockedPromise.state).isEqualTo(PromiseState.REJECTED)
    Truth.assertThat(mockedPromise.rejectMessage).isEqualTo(
      """
      Call to function 'test-1.f1' has been rejected.
      → Caused by: java.lang.NullPointerException
      """.trimIndent()
    )

    Truth.assertThat(mockedPromise2.state).isEqualTo(PromiseState.REJECTED)
    Truth.assertThat(mockedPromise2.rejectMessage).isEqualTo(
      """
      Call to function 'test-2.f1' has been rejected.
      → Caused by: Something went wrong
      """.trimIndent()
    )
  }

  @Test
  fun `call method should reject if method was called with incorrect arguments`() {
    val testCases = listOf(
      Triple(
        "test-1",
        "f10",
        JavaOnlyArray()
      ) to """
        Call to function 'test-1.f10' has been rejected.
        → Caused by: Method does not exist.
      """.trimIndent(),
      Triple(
        "test-1",
        "f1",
        JavaOnlyArray().apply { pushInt(1) }
      ) to """
        Call to function 'test-1.f1' has been rejected.
        → Caused by: Received 1 arguments, but 0 was expected.
      """.trimIndent(),
      Triple(
        "test-2",
        "f2",
        JavaOnlyArray().apply { pushString("string") }
      ) to """
        Call to function 'test-2.f2' has been rejected.
        → Caused by: Argument at index '0' couldn't be casted to type 'kotlin.Int' (received 'String').
        → Caused by: java.lang.ClassCastException: java.lang.String cannot be cast to java.lang.Number
      """.trimIndent(),
      Triple(
        "test-2",
        "f2",
        JavaOnlyArray()
      ) to """
        Call to function 'test-2.f2' has been rejected.
        → Caused by: Received 0 arguments, but 1 was expected.
      """.trimIndent(),
      Triple(
        "test-1",
        "f2",
        JavaOnlyArray().apply { pushMap(JavaOnlyMap().apply { putInt("string", 10) }) }
      ) to """
        Call to function 'test-1.f2' has been rejected.
        → Caused by: Argument at index '0' couldn't be casted to type 'expo.modules.kotlin.TestRecord' (received 'Map').
        → Caused by: Cannot create a record of the type: 'expo.modules.kotlin.TestRecord'.
        → Caused by: Cannot cast 'Number' for field 'string' ('kotlin.String').
        → Caused by: java.lang.ClassCastException: java.lang.Double cannot be cast to java.lang.String
      """.trimIndent()
    )

    testCases.forEach {
      val callValues = it.first
      val expected = it.second
      val promise = PromiseMock()

      interopModuleRegistry.callMethod(callValues.first, callValues.second, callValues.third, promise)

      Truth.assertThat(promise.state).isEqualTo(PromiseState.REJECTED)
      Truth.assertThat(promise.rejectMessage).isEqualTo(expected)
    }
  }
}
