package com.example.springboot3oauth2authorizationserver.security;

import com.example.springboot3oauth2authorizationserver.entity.Role;
import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.ArrayList;
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
        List<GrantedAuthority> authorities = mapper
                .readerForListOf(GrantedAuthority.class)
                .readValue(jsonNode.get("authorities"));

        Role role = authorities.isEmpty()
                ? new Role("ROLE_USER")
                : new Role(authorities.get(0).getAuthority());

//         List를 초기화하지 않아서 발생하는 오류를 방지
//        List<GrantedAuthority> authorities = new ArrayList<>();
//        JsonNode authoritiesNode = jsonNode.at("/authorities/1");
//        if (authoritiesNode.isArray()) {
//            for (JsonNode authorityNode : authoritiesNode) {
//                String authority = authorityNode.get("authority").asText();
//                authorities.add(new SimpleGrantedAuthority(authority));
//            }
//        }

        // 추출한 데이터를 사용하여 CustomUserPrincipal 객체를 생성하고 반환
        return new CustomUserPrincipal(id, username, password, role, enable, authorities);
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}
