package com.example.demo.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("kafka")
@RequiredArgsConstructor
public class Kafka {

    private final KafkaTemplate<String, String> kafkaTemplate;

    @GetMapping("push/my.topic")
    public ResponseEntity<?> push() {
        kafkaTemplate.send("my.topic", "test");
        return ResponseEntity.ok().build();
    }

    @KafkaListener(topics = "my.topic", groupId = "IDID", concurrency = "2")
    public void listen(ConsumerRecord<String, String> record) {
        try {
            log.info("topic: {}, record: {}", record.topic(), record.value());
//            Thread.sleep(TimeUnit.SECONDS.toMillis(1));
            Thread.sleep(50);
            log.info("topic: {}, record: {} ------ delivery", record.topic(), record.value());
        } catch (InterruptedException e) {
            log.error("error", e);
        }
    }
}
