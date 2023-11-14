package com.example.springboot3oauth2authorizationserver.security;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.List;

public class CustomUserPrincipalDeserializer extends JsonDeserializer<CustomUserPrincipal> {

    @Override
    public CustomUserPrincipal deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
        // ObjectMapper을 획득한다
        ObjectMapper mapper = (ObjectMapper) jsonParser.getCodec();

        // JSON 데이터를 읽고 JsonNode로 변환한다
        JsonNode jsonNode = mapper.readTree(jsonParser);

        // JsonNode에서 필요한 필드를 추출한다
        Long id = readJsonNode(jsonNode, "id").asLong();
        Boolean enable = readJsonNode(jsonNode, "enable").asBoolean();
        String username = readJsonNode(jsonNode, "username").asText();
        String password = readJsonNode(jsonNode, "password").asText();

        // authorities 필드를 List<GrantedAuthority>로 변환한다
        List<GrantedAuthority> authorities = mapper.readerForListOf(GrantedAuthority.class).readValue(jsonNode.get("authorities"));

        // 추출한 데이터를 사용하여 CustomUserPrincipal 객체를 생성하고 반환
        return new CustomUserPrincipal(id, username, password, enable, authorities);
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}
