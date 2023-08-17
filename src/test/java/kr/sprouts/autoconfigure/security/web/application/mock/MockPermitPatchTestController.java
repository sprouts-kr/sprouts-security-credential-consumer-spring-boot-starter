package kr.sprouts.autoconfigure.security.web.application.mock;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = MockPermitPatchTestController.REQUEST_PATH)
public class MockPermitPatchTestController {
    static final String REQUEST_PATH = "/mock/permit-patch";
    static final String BODY = "permitPatch";
    @GetMapping
    public ResponseEntity<String> get() {
        return ResponseEntity.ok(BODY);
    }

    @PostMapping
    public ResponseEntity<String> post() {
        return ResponseEntity.ok(BODY);
    }

    @PutMapping
    public ResponseEntity<String> put() {
        return ResponseEntity.ok(BODY);
    }

    @PatchMapping
    public ResponseEntity<String> patch() {
        return ResponseEntity.ok(BODY);
    }

    @DeleteMapping
    public ResponseEntity<String> delete() {
        return ResponseEntity.ok(BODY);
    }

    @PatchMapping(value = "/ext")
    public ResponseEntity<String> patchExt() {
        return ResponseEntity.ok(BODY);
    }
}
